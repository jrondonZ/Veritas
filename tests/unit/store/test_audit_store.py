import json

import pytest

from veritas.store import AuditChain, IntegrityError, Workspace, verify

N = 6


@pytest.fixture
def run(tmp_path):
    ws = Workspace(tmp_path)
    run = ws.create_run("assess", "sha256:" + "ab" * 32)
    for i in range(N):
        run.audit.append("test.event", n=i, note=f"entry {i}")
    yield ws, run
    ws.close()


def lines(run):
    return (run.dir / "audit.jsonl").read_text(encoding="utf-8").splitlines(keepends=True)


def rewrite(run, new_lines):
    (run.dir / "audit.jsonl").write_text("".join(new_lines), encoding="utf-8")


def test_intact_chain_verifies(run):
    ws, r = run
    result = ws.verify_run(r.id)
    assert result.ok, result.problems
    assert result.entries == N


@pytest.mark.parametrize("index", range(N))
def test_modified_entry_is_detected(run, index):
    ws, r = run
    ls = lines(r)
    entry = json.loads(ls[index])
    entry["note"] = "tampered"
    ls[index] = json.dumps(entry) + "\n"
    rewrite(r, ls)
    assert not ws.verify_run(r.id).ok


@pytest.mark.parametrize("index", range(N))
def test_deleted_entry_is_detected(run, index):
    ws, r = run
    ls = lines(r)
    del ls[index]
    rewrite(r, ls)
    assert not ws.verify_run(r.id).ok


@pytest.mark.parametrize("index", range(N - 1))
def test_swapped_entries_are_detected(run, index):
    ws, r = run
    ls = lines(r)
    ls[index], ls[index + 1] = ls[index + 1], ls[index]
    rewrite(r, ls)
    assert not ws.verify_run(r.id).ok


def test_rehashed_forgery_is_caught_by_the_index_head(run):
    """An attacker who recomputes every hash after an edit still diverges from the recorded head."""
    ws, r = run
    path = r.dir / "audit.jsonl"
    entries = [json.loads(line) for line in lines(r)]
    path.unlink()
    forged = AuditChain(path)
    for e in entries:
        forged.append("test.event", n=e["n"], note="forged" if e["n"] == 2 else e["note"])
    assert verify(path).ok  # internally consistent
    assert not ws.verify_run(r.id).ok  # but not the chain the kernel recorded


def test_appending_to_a_broken_log_is_refused(run):
    _, r = run
    ls = lines(r)
    ls[1] = ls[1].replace("entry 1", "entry X")
    rewrite(r, ls)
    with pytest.raises(ValueError, match="broken audit log"):
        AuditChain(r.dir / "audit.jsonl")


def test_reserved_field_names_are_rejected(run):
    _, r = run
    with pytest.raises(ValueError, match="reserved"):
        r.audit.append("x", prev="sha256:forged")


def test_blob_store_round_trip_and_integrity(tmp_path):
    ws = Workspace(tmp_path)
    ref = ws.blobs.put(b"hello")
    assert ws.blobs.get(ref) == b"hello"
    assert ws.blobs.put(b"hello") == ref
    ws.blobs.path_for(ref).write_bytes(b"jello")
    with pytest.raises(IntegrityError):
        ws.blobs.get(ref)
    ws.close()


def test_evidence_ids_are_content_derived(tmp_path):
    ws = Workspace(tmp_path)
    r = ws.create_run("assess", None)
    first = ws.add_evidence(r.id, b'{"request": 1}', "application/json", "gateway")
    again = ws.add_evidence(r.id, b'{"request": 1}', "application/json", "gateway")
    assert first == again
    assert first.startswith("E-")
    assert len(first) == 14
    ws.close()


def test_run_ids_are_sequential(tmp_path):
    ws = Workspace(tmp_path)
    assert [ws.create_run("assess", None).id for _ in range(3)] == ["r-0001", "r-0002", "r-0003"]
    ws.close()
