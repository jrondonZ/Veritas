"""Fixed-field terminal output: no prose, one labeled line per fact (docs/architecture.md §12.1)."""

from __future__ import annotations

from typing import Any

LABELS = {
    "observed": "observed",
    "inferred": "inferred",
    "unknown": "unknown",
    "limitation": "limit",
    "guidance": "fix",
}


def _finding(f: dict[str, Any]) -> list[str]:
    severity = (f.get("severity") or "—").upper() if f["status"] == "confirmed" else "—"
    status = f["status"] + (f" {f['passed']}/{f['attempts']}" if f["status"] == "confirmed" else "")
    lines = [f"{severity:<8}{f['id']}  {f['title']:<70} {status}"]
    pad = " " * 8
    if f["status"] != "confirmed":
        lines.append(f"{pad}reason    {f['reason']}")
        return lines
    tags = " · ".join([*f["cwe"], *f["wstg"]])
    if f.get("cvss"):
        tags += f" · {f['cvss']['vector']} {f['cvss']['score']}"
    lines.append(f"{pad}{tags}")
    for claim in f["claims"]:
        refs = "  " + " ".join(claim["evidence"]) if claim["evidence"] else ""
        refs += "  ← " + " ".join(claim["based_on"]) if claim["based_on"] else ""
        label = ("~" if "@" in claim.get("producer", "") else "") + LABELS[claim["kind"]]  # ~ marks model-written
        lines.append(f"{pad}{label:<9} {claim['text']}{refs}")
    if (f.get("cvss") or {}).get("source") == "model-adjusted":
        lines.append(f"{pad}{'~cvss':<9} adjusted from the check default {f['cvss']['default']}")
    for i, step in enumerate(f["repro"], 1):
        lines.append(f"{pad}{'repro' if i == 1 else '':<9} {i}. {step}")
    return lines


def render_terminal(document: dict[str, Any], show_rejected: bool = False) -> list[str]:
    s = document["summary"]
    lines = [
        f"run      {document['run']} · {document['outcome']} · {document['duration_s']} s · "
        f"scope {document['scope']['name']} {document['scope']['digest'][:19]}…",
        f"summary  {s['confirmed']} confirmed · {s['rejected']} rejected · {s['inconclusive']} inconclusive · "
        f"{s['blocked']} blocked · {s['error']} errors",
    ]
    if document.get("message"):
        lines.append(f"aborted  {document['message']}")
    shown = [f for f in document["findings"] if show_rejected or f["status"] != "rejected"]
    for finding in sorted(shown, key=lambda f: (f["status"] != "confirmed", f["id"])):
        lines += ["", *_finding(finding)]
    lines.append("")
    coverage = " · ".join(f"{c['wstg']} {c['status']}" for c in document["coverage"])
    lines.append(f"coverage {coverage}")
    lint = document.get("lint")  # absent in documents written before the claim linter
    if lint is not None:
        problems = lint["problems"]
        state = f"{len(problems)} problems · {lint['dropped']} dropped" if problems else "every reference resolves"
        lines.append(f"claims   {lint['claims']} typed · {state}")
    models = document.get("models")
    if models and models.get("status") == "on":
        served = models["routes"]["analysis"]
        lines.append(
            f"models   local {served['model']} · {models['calls']} calls · {models['cache_hits']} cached · "
            f"{models['tokens']} tokens · {models['duration_s']} s · ~ marks model-written claims"
        )
    elif models:
        lines.append(f"models   {models['status']}" + (f": {models['reason']}" if models.get("reason") else ""))
    return lines
