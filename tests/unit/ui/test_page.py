"""The central page: one file opened from disk, which runs only its own script and shows the workspace as data."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from veritas.cli.output import refresh_page
from veritas.store import Workspace
from veritas.ui import page

HOSTILE = "</script><script>alert(1)</script><!-- &     </style>"


def _assess_run(ws: Workspace, title: str = "Reflected HTML: GET /search") -> str:
    run = ws.create_run("assess", "sha256:" + "0" * 64)
    run.audit.append("run.start", note="test")
    document = {
        "scope": {"name": "demo"},
        "summary": {"confirmed": 1},
        "target": {"base_url": "http://lab.invalid"},
        "findings": [{"id": "F-0001", "title": title, "status": "confirmed", "severity": "high", "claims": []}],
    }
    (run.dir / "findings.json").write_text(json.dumps(document), encoding="utf-8")
    (run.dir / "report.md").write_text("# report\n", encoding="utf-8")
    (run.dir / "notes.txt").write_text("not on the allowlist\n", encoding="utf-8")
    ws.set_outcome(run.id, "completed")
    return run.id


@pytest.fixture
def root(tmp_path: Path) -> Path:
    ws = Workspace(tmp_path)
    try:
        _assess_run(ws, HOSTILE)
    finally:
        ws.close()
    return tmp_path


def _parts(html: str) -> tuple[str, str, str, str]:
    csp = re.search(r'http-equiv="Content-Security-Policy" content="([^"]*)"', html)
    style = re.search(r"<style>(.*?)</style>", html, re.S)
    blob = re.search(r'<script type="application/json" id="veritas-data">(.*?)</script>', html, re.S)
    script = re.search(r"<script>(.*?)</script>\s*</body>", html, re.S)
    assert csp and style and blob and script
    return csp.group(1), style.group(1), blob.group(1), script.group(1)


def _sha(text: str) -> str:
    return "'sha256-" + base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode("ascii") + "'"


def test_the_policy_allows_exactly_the_inline_script_and_style(root: Path) -> None:
    csp, style, _, script = _parts(page.build(root))
    assert f"script-src {_sha(script)};" in csp
    assert f"style-src {_sha(style)};" in csp
    assert csp.startswith("default-src 'none';")  # no fetches, frames, fonts, or connections
    assert "unsafe" not in csp and "http" not in csp and "*" not in csp
    assert "base-uri 'none'" in csp and "form-action 'none'" in csp


def test_target_text_stays_data_and_round_trips(root: Path) -> None:
    html = page.build(root)
    _, _, blob, _ = _parts(html)
    assert "<" not in blob and ">" not in blob and "&" not in blob
    assert " " not in blob and " " not in blob
    assert html.count("<script") == 2  # the data block and the page's own script, nothing smuggled in
    snapshot = json.loads(blob)
    (run,) = snapshot["runs"].values()
    assert run["assessment"]["findings"][0]["title"] == HOSTILE


def test_the_page_reads_nothing_from_anywhere() -> None:
    for name in ("page.html", "app.css", "app.js"):
        text = (page.STATIC / name).read_text(encoding="utf-8")
        assert not re.search(r"https?:|//[a-z0-9.-]+\.[a-z]{2,}/", text, re.I), name
    css = (page.STATIC / "app.css").read_text(encoding="utf-8")
    assert "url(" not in css and "@import" not in css
    script = (page.STATIC / "app.js").read_text(encoding="utf-8")
    for api in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "Function(", "fetch(",
                "XMLHttpRequest", "WebSocket", "localStorage", "import("):  # fmt: skip
        assert api not in script, api


def test_assets_that_could_end_their_own_element_are_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    static = tmp_path / "static"
    shutil.copytree(page.STATIC, static)
    (static / "app.js").write_text('console.log("</script>");\n', encoding="utf-8")
    monkeypatch.setattr(page, "STATIC", static)
    with pytest.raises(ValueError, match="closing tag"):
        page.build(tmp_path)


def test_newest_runs_carry_their_documents(tmp_path: Path) -> None:
    ws = Workspace(tmp_path)
    try:
        ids = [_assess_run(ws) for _ in range(3)]
    finally:
        ws.close()
    snapshot = page.snapshot(tmp_path, max_details=2)
    assert [r["id"] for r in snapshot["overview"]["runs"]] == ids[::-1]  # every run is listed
    assert sorted(snapshot["runs"]) == ids[1:]  # the newest two in full
    assert snapshot["kept"] == 2
    detail = snapshot["runs"][ids[2]]
    assert detail["audit"]["ok"] is True
    assert detail["files"] == ["report.md"]  # only allowlisted names; notes.txt stays off the page


def test_patch_drafts_carry_their_diff(tmp_path: Path) -> None:
    ws = Workspace(tmp_path)
    try:
        run = ws.create_run("analyze", None)
        run.audit.append("run.start", note="test")
        patches = run.dir / "patches"
        patches.mkdir()
        (patches / "S-0001.diff").write_text("--- a/x.mjs\n+++ b/x.mjs\n", encoding="utf-8")
        record = {"finding": "S-0001", "status": "answered", "verified": True, "diff": "S-0001.diff"}
        (patches / "S-0001.json").write_text(json.dumps(record), encoding="utf-8")
    finally:
        ws.close()
    (detail,) = page.snapshot(tmp_path)["runs"].values()
    assert detail["patches"][0]["diff_text"].startswith("--- a/x.mjs")
    assert "patches/S-0001.diff" in detail["files"]


def test_an_empty_folder_still_gets_a_page(tmp_path: Path) -> None:
    html = page.build(tmp_path)
    _, _, blob, _ = _parts(html)
    assert json.loads(blob)["overview"]["runs"] == []
    assert not (tmp_path / ".veritas").exists()  # building reads; only publishing writes


def test_publish_replaces_the_page_whole(root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = page.publish(root)
    first = path.read_text(encoding="utf-8")
    assert path == root / ".veritas" / "index.html" and first.startswith("<!doctype html>")

    def refuse(*_: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(page.os, "replace", refuse)
    with pytest.raises(OSError):
        page.publish(root)
    assert path.read_text(encoding="utf-8") == first  # the old page survives a failed write
    assert sorted(p.name for p in (root / ".veritas").glob("*.html")) == ["index.html"]  # and no temp file is left


def test_refreshing_only_warns(root: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    def broken(_: Path) -> Path:
        raise RuntimeError("boom")

    monkeypatch.setattr(page, "publish", broken)
    refresh_page(root)  # a command's result never depends on the page
    assert "wasn't updated" in capsys.readouterr().out


def test_refreshing_never_creates_a_workspace(tmp_path: Path) -> None:
    refresh_page(tmp_path)
    assert not (tmp_path / ".veritas").exists()


def _analysis_run(ws: Workspace) -> None:
    """An analysis run's documents, written as plain files, so every tab has something to show."""
    run = ws.create_run("analyze", None)
    run.audit.append("run.start", note="test")
    finding = {"id": "S-0001", "rule": "html-from-input", "title": HOSTILE, "status": "candidate", "cwe": ["CWE-79"],
               "if_confirmed": {"severity": "medium", "cvss": {"vector": "CVSS:3.1/AV:N", "score": 6.1}},
               "file": "app/server.mjs", "line": 3, "function": "search", "confirms_with": "reflected-html",
               "claims": [{"kind": "observed", "text": HOSTILE, "evidence": ["E-0123456789ab"]}]}  # fmt: skip
    documents = {
        "analysis.json": {"charter": {"name": "demo", "basis": "owned"}, "limitations": [HOSTILE],
                          "subjects": [{"path": "app/server.mjs", "type": "javascript", "staged": "x-server.mjs",
                                        "sha256": "ab" * 32, "counts": {"functions": 3}}],
                          "spec": {"claims": 1}, "code": {"candidates": 1}},
        "spec.json": {"digest": "sha256:" + "1" * 64,
                      "interfaces": [{"id": "IF-http", "title": "HTTP", "claims": [{"kind": "observed", "text": "x"}]}]},
        "code-findings.json": {"findings": [finding]},
    }  # fmt: skip
    for name, document in documents.items():
        (run.dir / name).write_text(json.dumps(document), encoding="utf-8")
    clean = run.dir / "cleanroom" / "verify-1"
    clean.mkdir(parents=True)
    (clean / "conformance.json").write_text(json.dumps({"passed": 9, "total": 12}), encoding="utf-8")
    (clean / "similarity.json").write_text(json.dumps({"overall": 0.04, "limit": 0.25, "similar": False}), "utf-8")
    patches = run.dir / "patches"
    patches.mkdir()
    (patches / "S-0001.diff").write_text("--- a/x\n+++ b/x\n@@ -1 +1 @@\n-old\n+new\n", encoding="utf-8")
    record = {"finding": "S-0001", "status": "answered", "verified": True, "diff": "S-0001.diff", "reason": "",
              "notes": HOSTILE, "verification": {"parses": True, "finding_gone": True, "new_findings": []}}  # fmt: skip
    (patches / "S-0001.json").write_text(json.dumps(record), encoding="utf-8")


@pytest.mark.skipif(shutil.which("node") is None, reason="needs Node.js")
def test_every_view_renders(root: Path) -> None:
    ws = Workspace(root)
    try:
        _analysis_run(ws)
    finally:
        ws.close()
    path = page.publish(root)
    smoke = Path(__file__).with_name("dom_smoke.mjs")
    done = subprocess.run(["node", str(smoke), str(path)], capture_output=True, text=True, timeout=120, check=False)
    assert done.returncode == 0, done.stderr
    assert done.stdout.startswith("ok ")
