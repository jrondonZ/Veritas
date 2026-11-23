"""Markdown report for people (docs/architecture.md §12.2)."""

from __future__ import annotations

from typing import Any

KIND = {
    "observed": "Observed",
    "inferred": "Inferred",
    "unknown": "Unknown",
    "limitation": "Limitation",
    "guidance": "Fix",
}


def _cell(text: object) -> str:
    return _text(text).replace("|", "\\|")


def _text(text: object) -> str:
    """Claim text can come from a model that read target data, so it is never rendered as markup."""
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\n", " ")


def _models(models: dict[str, Any] | None, recon: dict[str, Any] | None) -> list[str]:
    if not models:
        return []
    out = ["## Models", ""]
    if models.get("status") != "on":
        reason = f": {_text(models['reason'])}" if models.get("reason") else ""
        return [*out, f"- {models.get('status', 'off')}{reason}", ""]
    out += [f"- Profile `{models['profile']}`, all local; claims marked *(model)* were written by the model named."]
    for route, r in models["routes"].items():
        if not r.get("available"):
            out.append(f"- `{route}`: unavailable")
            continue
        via = f" (aliased to `{r['aliased_to']}`)" if r.get("aliased_to") else ""
        out.append(f"- `{route}`{via}: {r['model']} · {r['quantization']} · {r['license']} · `{r['weights'][:19]}…`")
    out.append(f"- {models['calls']} model calls · {models['cache_hits']} answered from cache · {models['tokens']} "
               f"tokens · {models['duration_s']} s")  # fmt: skip
    labels = (recon or {}).get("labels")
    if labels:
        out += ["", "| Route | Sensitivity (triage) | Note |", "|---|---|---|"]
        out += [f"| {_cell(r)} | {v['sensitivity']} | {_cell(v['note'])} |" for r, v in labels["routes"].items()]
    return [*out, ""]


def render_markdown(document: dict[str, Any]) -> str:
    s = document["summary"]
    out = [
        f"# Veritas report: {document['scope']['name']} ({document['run']})",
        "",
        "| | |",
        "|---|---|",
        f"| Outcome | {document['outcome']} |",
        f"| Target | {document['target']['id']} ({document['target']['base_url']}) |",
        f"| Scope digest | `{document['scope']['digest']}` |",
        f"| Started | {document['started']} ({document['duration_s']} s) |",
        f"| Veritas | {document['veritas']} |",
        "",
        "## Summary",
        "",
        "| Confirmed | Rejected | Inconclusive | Blocked | Error |",
        "|---|---|---|---|---|",
        f"| {s['confirmed']} | {s['rejected']} | {s['inconclusive']} | {s['blocked']} | {s['error']} |",
        "",
    ]
    if document.get("message"):
        out += [f"**Run aborted:** {document['message']}", ""]
    confirmed = [f for f in document["findings"] if f["status"] == "confirmed"]
    if confirmed:
        out += ["## Confirmed findings", ""]
    for f in confirmed:
        cvss = f" · `{f['cvss']['vector']}` {f['cvss']['score']}" if f.get("cvss") else ""
        out += [
            f"### {f['id']} · {(f.get('severity') or '').upper()} · {f['title']}",
            "",
            f"- Reproduced {f['passed']} of {f['attempts']} attempts · {' · '.join([*f['cwe'], *f['wstg']])}{cvss}",
        ]
        for claim in f["claims"]:
            refs = f" ({', '.join(claim['evidence'])})" if claim["evidence"] else ""
            basis = f" (from {', '.join(claim['based_on'])})" if claim["based_on"] else ""
            by = f" *(model: {_text(claim['producer'])})*" if "@" in claim.get("producer", "") else ""
            out.append(f"- **{KIND[claim['kind']]}** {_text(claim['text'])}{refs}{basis}{by}")
        if (f.get("cvss") or {}).get("source") == "model-adjusted":
            out.append(f"- **CVSS** adjusted by a model from the check default `{f['cvss']['default']}`")
        out += ["- **Reproduce**", *[f"  {i}. {step}" for i, step in enumerate(f["repro"], 1)], ""]
    others = [f for f in document["findings"] if f["status"] != "confirmed"]
    if others:
        out += ["## Not confirmed", "", "| ID | Check | Route | Status | Reason |", "|---|---|---|---|---|"]
        out += [
            f"| {f['id']} | {f['check']} | {_cell(f['route'])} | {f['status']} | {_cell(f['reason'])} |" for f in others
        ]
        out.append("")
    out += ["## Coverage (OWASP WSTG)", "", "| Test | Check | Status | Probes |", "|---|---|---|---|"]
    out += [f"| {c['wstg']} | {c['check']} | {c['status']} | {c['probes']} |" for c in document["coverage"]]
    out += ["", "Coverage is limited to the tests listed; this phase does not assess other WSTG tests.", ""]
    recon = document.get("recon")
    if recon:
        out += [
            "## Recon",
            "",
            f"- Routes: {len(recon['routes'])}; fetches: {recon['fetches']}; "
            f"sign-ins: {', '.join(recon['logins']) or 'none'}",
        ]
        if recon["external_links"]:
            out.append(f"- External links recorded, not fetched: {', '.join(recon['external_links'])}")
        if recon["skipped"]:
            out.append(f"- In-origin links not followed: {', '.join(recon['skipped'])}")
        out.append("")
    out += _models(document.get("models"), recon)
    return "\n".join(out)
