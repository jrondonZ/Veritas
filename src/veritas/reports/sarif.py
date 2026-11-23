"""SARIF 2.1.0 for code-scanning tools (docs/architecture.md §12.2).

Confirmed findings are `fail` results; inconclusive ones are `review` results with
level `none`. Web findings carry `webRequest` and `webResponse` built from evidence.
"""

from __future__ import annotations

from typing import Any

from .. import __version__

SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}


def web_objects(exchange: Any) -> dict[str, Any]:
    """`webRequest`/`webResponse` from an Exchange (headers are already masked at capture)."""
    return {
        "webRequest": {
            "protocol": "HTTP",
            "version": "1.1",
            "method": exchange.method,
            "target": exchange.path,
            "headers": dict(exchange.request_headers),
        },
        "webResponse": {
            "protocol": "HTTP",
            "version": "1.1",
            "statusCode": exchange.status,
            "headers": dict(exchange.response_headers),
        },
    }


def render_sarif(document: dict[str, Any], exchanges: dict[str, Any]) -> dict[str, Any]:
    reported = [f for f in document["findings"] if f["status"] in ("confirmed", "inconclusive")]
    rules: dict[str, dict[str, Any]] = {}
    results = []
    for f in reported:
        rule = rules.setdefault(
            f["check"],
            {
                "id": f["check"],
                "shortDescription": {"text": f["title"].split(":")[0]},
                "properties": {"tags": ["security", *f["cwe"], *f["wstg"]]},
            },
        )
        if f.get("cvss"):
            rule["properties"]["security-severity"] = str(f["cvss"]["score"])
        guidance = next((c["text"] for c in f["claims"] if c["kind"] == "guidance"), None)
        if guidance:
            rule["help"] = {"text": guidance}
        result: dict[str, Any] = {
            "ruleId": f["check"],
            "kind": "fail" if f["status"] == "confirmed" else "review",
            "level": LEVEL.get(f.get("severity") or "", "warning") if f["status"] == "confirmed" else "none",
            "message": {"text": f"{f['title']} ({f['status']}: {f['reason']})"},
            "locations": [{"logicalLocations": [{"fullyQualifiedName": f["route"], "kind": "resource"}]}],
            "partialFingerprints": {"veritas/v1": f["fingerprint"]},
            "properties": {
                "veritasId": f["id"],
                "reproducibility": f"{f['passed']}/{f['attempts']}",
                "claims": [f"{c['kind']}: {c['text']}" for c in f["claims"]],
            },
        }
        evidence = next((e for c in f["claims"] for e in c["evidence"]), None)
        if evidence in exchanges:
            result.update(exchanges[evidence])
        results.append(result)
    return {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "Veritas", "version": __version__, "rules": list(rules.values())}},
                "invocations": [{"executionSuccessful": document["outcome"] != "aborted"}],
                "results": results,
            }
        ],
    }
