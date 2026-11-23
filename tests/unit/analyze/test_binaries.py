"""The binary engine: native samples and a compiled .NET tool against their ground truth, and hostile files."""

import asyncio
import importlib.util
import json
import shutil
import struct
from pathlib import Path

import pytest

from veritas.analyze.charter import check_charter
from veritas.analyze.ground import compare_code
from veritas.analyze.program import FileModel
from veritas.analyze.runner import _run, local_launcher
from veritas.analyze.security import code_findings
from veritas.core.canonical import sha256_hex
from veritas.documents import load_yaml
from veritas.store import Workspace

SAMPLES = ("weak-elf", "hardened-elf", "weak.exe", "hardened.exe", "weak-macho", "hardened-macho")


def models(run_binary_engine, folder: Path, names, prefix=""):
    files = [{"path": n, "sha256": sha256_hex((folder / n).read_bytes())} for n in names]
    results = run_binary_engine(folder, files)
    assert all("error" not in r for r in results), [r.get("error") for r in results]
    return [FileModel(f"{prefix}{r['path']}", r["sha256"], f"E-{n:012x}", r) for n, r in enumerate(results, 1)]


@pytest.fixture(scope="module")
def native(repo_root):
    return repo_root / "labs" / "native-samples"


@pytest.fixture(scope="module")
def notes_cli(repo_root):
    return repo_root / "labs" / "notes-cli"


def test_the_native_samples_yield_exactly_the_expected_candidates(run_binary_engine, native):
    found = code_findings(models(run_binary_engine, native / "dist", SAMPLES, prefix="dist/"))
    outcome = compare_code(found, load_yaml(native / "expected-code-findings.yaml"))
    assert (outcome.precision, outcome.recall) == (1.0, 1.0), (outcome.unexpected, outcome.missed)
    assert outcome.look_alikes == []  # the hardened twins stay quiet


def test_each_format_reports_its_hardening(run_binary_engine, native):
    facts = {m.path: m.facts for m in models(run_binary_engine, native / "dist", SAMPLES)}
    assert facts["weak-elf"]["hardening"] | {"rpath": None} == {"pie": False, "nx": False, "relro": "none",
        "canary": False, "fortify": False, "wx_sections": ["segment 1"], "rpath": None, "runpath": []}  # fmt: skip
    assert (facts["hardened-elf"]["hardening"]["relro"], facts["hardened-elf"]["hardening"]["canary"]) == ("full", True)
    assert {k: facts["weak.exe"]["hardening"][k] for k in ("aslr", "dep", "cfg")} == {"aslr": False, "dep": False,
                                                                                      "cfg": False}  # fmt: skip
    assert {k: facts["hardened.exe"]["hardening"][k] for k in ("aslr", "dep", "cfg")} == {"aslr": True, "dep": True,
                                                                                          "cfg": True}  # fmt: skip
    assert facts["weak.exe"]["libraries"] == ["KERNEL32.dll", "msvcrt.dll"]
    assert facts["weak-macho"]["banned"] == [
        {"name": "gets", "kind": "dangerous"},
        {"name": "strcpy", "kind": "banned"},
    ]
    assert facts["hardened-macho"]["hardening"]["canary"] is True
    assert all(s["value"] != "libc.so.6" for s in facts["weak-elf"]["strings"])  # structure, not a literal


def test_the_committed_samples_are_what_the_generator_builds(native, tmp_path):
    spec = importlib.util.spec_from_file_location("make_samples", native / "tools" / "make_samples.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.main(tmp_path)
    for name in SAMPLES:
        assert (tmp_path / name).read_bytes() == (native / "dist" / name).read_bytes(), name


def test_the_dotnet_tool_yields_exactly_the_expected_candidates(run_binary_engine, notes_cli):
    (model,) = models(run_binary_engine, notes_cli / "dist", ["NotesCli.exe"], prefix="dist/")
    found = code_findings([model])
    outcome = compare_code(found, load_yaml(notes_cli / "expected-code-findings.yaml"))
    assert (outcome.precision, outcome.recall) == (1.0, 1.0), (outcome.unexpected, outcome.missed)
    assert outcome.look_alikes == []
    managed = model.facts["dotnet"]
    assert managed["assembly"] == {"name": "NotesCli", "version": "0.0.0.0"}
    assert {r["name"] for r in managed["references"]} >= {"mscorlib", "System.Data", "System.Xml"}
    assert managed["il"]["undecoded"] == 0
    assert "NotesCli.Store::SearchSafe" in {e["name"] for e in model.facts["exports"]}
    (secret,) = [f for f in found if f["rule"] == "hardcoded-secret"]
    assert "AKIAVRTFAKEKEY000001" not in json.dumps(secret)


def hostile(tmp_path, name, data):
    (tmp_path / name).write_bytes(data)
    return {"path": name, "sha256": sha256_hex(data)}


def test_hostile_files_fail_to_parse_instead_of_crashing(run_binary_engine, native, tmp_path):
    weak = (native / "dist" / "weak.exe").read_bytes()
    elf = (native / "dist" / "weak-elf").read_bytes()
    files = [
        hostile(tmp_path, "truncated.exe", weak[:300]),
        hostile(tmp_path, "far.exe", weak[:0x3C] + struct.pack("<I", 0x7FFFFFF0) + weak[0x40:]),
        hostile(tmp_path, "headers.elf", elf[:32] + struct.pack("<Q", 0xFFFFFFFFFFF0) + elf[40:]),
        hostile(tmp_path, "text.bin", b"just some text that isn't an executable at all, padded out" * 2),
        hostile(tmp_path, "java.class", b"\xca\xfe\xba\xbe\x00\x00\x00\x34" + b"\0" * 64),
        hostile(tmp_path, "empty.bin", b""),
    ]
    results = run_binary_engine(tmp_path, files)
    assert [r["path"] for r in results] == [f["path"] for f in files]
    assert all(r.get("error") for r in results), results
    assert all(not r["error"].startswith("analysis failed") for r in results), [r["error"] for r in results]


SYSTEM = [Path(p) for p in ("C:/Windows/System32/notepad.exe", "/bin/ls", "/usr/bin/true")]


@pytest.mark.parametrize("path", [p for p in SYSTEM if p.is_file()] or [pytest.param(None, marks=pytest.mark.skip)])
def test_a_real_system_binary_parses(run_binary_engine, path, tmp_path):
    shutil.copyfile(path, tmp_path / path.name)
    (result,) = run_binary_engine(tmp_path, [{"path": path.name, "sha256": sha256_hex(path.read_bytes())}])
    assert "error" not in result, result.get("error")
    assert result["libraries"]
    assert result["imports"]
    json.dumps(result)


@pytest.fixture
def cli_run(tmp_path, repo_root, notes_cli, node):
    report = check_charter(notes_cli / "veritas.charter.yaml")
    assert report.ok, report.errors
    ws = Workspace(tmp_path)
    result = asyncio.run(_run(ws, report, report.charter, report.digest, repo_root, local_launcher(repo_root, node),
                              lambda a, b: None))  # fmt: skip
    yield ws, result
    ws.close()


def test_an_analysis_of_the_assembly_states_its_interface_and_its_gaps(cli_run, notes_cli):
    ws, result = cli_run
    assert result.outcome == "completed_with_gaps"  # compiled code has no source for the similarity audit
    assert any("no source to compare" in text for text in result.document["limitations"])
    outcome = compare_code(result.code, load_yaml(notes_cli / "expected-code-findings.yaml"))
    assert (outcome.precision, outcome.recall, outcome.look_alikes) == (1.0, 1.0, [])
    clean = json.loads((ws.runs_dir / result.run_id / "spec.json").read_text(encoding="utf-8"))
    texts = {i["id"]: " ".join(c["text"] for c in i["claims"]) for i in clean["interfaces"]}
    assert "It's the .NET assembly `NotesCli` version 0.0.0.0" in texts["IF-binary"]
    assert "It references the assembly `System.Data`" in texts["IF-platform"]
    assert "`NotesCli.Store::Search` is exported as a function taking 1 argument(s)." in texts["IF-api"]
    (subject,) = result.document["subjects"]
    assert (subject["type"], subject["counts"]["types"], subject["counts"]["methods"]) == ("pe", 4, 12)
