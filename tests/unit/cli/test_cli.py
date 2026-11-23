from typer.testing import CliRunner

from veritas.cli import app
from veritas.cli.output import EXIT_INVALID
from veritas.store import Workspace

runner = CliRunner()


def test_scope_check_valid_lab_scope(repo_root):
    result = runner.invoke(app, ["scope", "check", str(repo_root / "labs/vuln-notes/veritas.scope.yaml"), "--no-ack"])
    assert result.exit_code == 0, result.output
    assert "172.30.0.4 (private)" in result.output
    assert "approval required: sensitive" in result.output


def test_scope_check_invalid_scope_exits_4(tmp_path):
    bad = tmp_path / "scope.yaml"
    bad.write_text(
        "apiVersion: veritas/v1alpha1\nkind: AssessmentScope\nenvironment: {kind: production}\n", encoding="utf-8"
    )
    result = runner.invoke(app, ["scope", "check", str(bad), "--no-ack"])
    assert result.exit_code == EXIT_INVALID
    assert "production environments are not supported" in result.output


def test_scope_check_refuses_to_acknowledge_without_a_terminal(tmp_path, monkeypatch, repo_root):
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["scope", "check", str(repo_root / "labs/vuln-notes/veritas.scope.yaml")])
    assert result.exit_code == EXIT_INVALID
    assert "interactive terminal" in result.output


def test_audit_verify_detects_tampering(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    ws = Workspace(tmp_path)
    run = ws.create_run("assess", None)
    for i in range(3):
        run.audit.append("test.event", n=i)
    ws.close()
    ok = runner.invoke(app, ["audit", "verify", run.id])
    assert ok.exit_code == 0, ok.output
    assert "3 entries" in ok.output
    log = run.dir / "audit.jsonl"
    log.write_text(log.read_text(encoding="utf-8").replace('"n":1', '"n":9'), encoding="utf-8")
    bad = runner.invoke(app, ["audit", "verify", run.id])
    assert bad.exit_code == 1, bad.output
    assert "modified" in bad.output


SCOPE_WITH_ESCAPE = """\
apiVersion: veritas/v1alpha1
kind: AssessmentScope
metadata: {name: esc-test}
authorization:
  basis: owned
  reference: {file: "missing\\e[2J.md"}
  window: {start: 2026-01-01T00:00:00Z, end: 2099-01-01T00:00:00Z}
environment: {kind: local-dev}
targets:
  - id: web
    base_url: http://localhost:8080
    addresses: [127.0.0.1]
    allow: {paths: ["/"], methods: [GET]}
    limits: {rps: 1, concurrency: 1, max_requests: 10}
"""


def test_control_characters_are_stripped_from_output(tmp_path):
    scope = tmp_path / "scope.yaml"
    scope.write_text(SCOPE_WITH_ESCAPE, encoding="utf-8")
    result = runner.invoke(app, ["scope", "check", str(scope), "--no-ack"])
    assert result.exit_code == EXIT_INVALID
    assert "reference.file not found" in result.output  # the error echoes the raw file name...
    assert "\x1b" not in result.output
    assert "missing?[2J.md" in result.output
