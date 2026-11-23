"""The relay protocol, the llama.cpp adapter, and the model-call contract, against a stand-in server."""

import asyncio
import json
import sys
from pathlib import Path

import pytest

from veritas.models.cache import ResponseCache
from veritas.models.calls import ModelService, ModelTask, TokenBudget, answer_envelope
from veritas.models.profiles import PROFILES, Profile, Routing
from veritas.models.prompts import Prompt
from veritas.models.registry import RegisteredModel
from veritas.models.server import http_request, parse_response
from veritas.sandbox.model import ModelLimits
from veritas.store import Workspace

FAKE = Path(__file__).with_name("fake_relay.py")
MODEL = RegisteredModel("tiny", "sha256:" + "ab" * 32, 1, "tiny.gguf", "mit", "Q4_K_M", "qwen3", 8192, "Tiny", "t")
SCHEMA = answer_envelope({"summary": {"type": "string", "maxLength": 200}}, ["summary"])
TINY_CONTEXT = Profile("tiny", "test", ModelLimits("1g", 1, 1, 64), {"analysis": None})


class FakeSandbox:
    name = "fake-model"

    def __init__(self, argv):
        self.argv, self.ups, self.downs = argv, 0, 0

    def up(self):
        self.ups += 1

    def relay_argv(self):
        return self.argv

    def logs(self):
        return ""

    def down(self):
        self.downs += 1


@pytest.fixture
def server(tmp_path, monkeypatch):
    """Script the stand-in's answers; returns the relay argv and the path of its request log."""

    def script(*answers, loading=0, refuse=0):
        answers_file = tmp_path / f"answers-{len(list(tmp_path.glob('answers-*')))}.json"
        answers_file.write_text(json.dumps(list(answers)), encoding="utf-8")
        log = tmp_path / "requests.jsonl"
        for name, value in (("FAKE_ANSWERS_FILE", answers_file), ("FAKE_LOG", log), ("FAKE_LOADING", loading),
                            ("FAKE_REFUSE", refuse)):  # fmt: skip
            monkeypatch.setenv(name, str(value))
        return [sys.executable, "-I", str(FAKE)], log

    return script


@pytest.fixture
def workspace(tmp_path):
    ws = Workspace(tmp_path)
    yield ws
    ws.close()


def make_service(tmp_path, ws, argv, *, budget=1_000_000, profile=None, choices=None):
    run = ws.create_run("assess", "sha256:test")
    routing = Routing(profile or PROFILES["laptop"], {"analysis": "tiny"} if choices is None else choices,
                      {"tiny": MODEL})  # fmt: skip
    boxes = []

    def factory(model):
        boxes.append(FakeSandbox(argv))
        return boxes[-1]

    service = ModelService(routing, "sha256:image", run.id, run.audit, ResponseCache(tmp_path), TokenBudget(budget),
                           sandbox_factory=factory)  # fmt: skip
    return service, run, boxes


def answer(summary="Any signed-in user can read any note.", **changes):
    return {"status": "answered", "reason": "none", "escalate": "none", "summary": summary, **changes}


def task(check=lambda output: []):
    prompt = Prompt("analyst", "1", "Summarize the finding.", "REFERENCE", "TASK DATA")
    return ModelTask("analyst", "analysis", "F-0001", prompt, SCHEMA, 64, check)


def run_tasks(service, *tasks):
    async def main():
        try:
            return [await service.run(t) for t in tasks]
        finally:
            await service.close()

    return asyncio.run(main())


def events(run):
    return [json.loads(line) for line in (run.dir / "audit.jsonl").read_text(encoding="utf-8").splitlines()]


def requests(log):
    return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]


def test_http_framing():
    assert http_request("POST", "/tokenize", b"{}").startswith(b"POST /tokenize HTTP/1.1\r\nHost: 127.0.0.1\r\n")
    assert b"Connection: close" in http_request("GET", "/health")
    chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n"
    assert parse_response("POST", chunked) == (200, b"Wikipedia")


def test_an_answer_is_validated_audited_and_attributed(tmp_path, workspace, server):
    argv, log = server(answer(), loading=1, refuse=1)
    service, run, boxes = make_service(tmp_path, workspace, argv)
    (result,) = run_tasks(service, task())
    assert (result.status, result.calls, result.output["summary"]) == ("answered", 1, answer()["summary"])
    assert (result.producer, result.serving, result.aliased) == ("analyst@tiny:abababababab", "analysis", False)
    assert [e["type"] for e in events(run)] == ["model.start", "model.call", "model.stop"]
    call = events(run)[1]
    assert (call["cache_hit"], call["prompt_tokens"], call["status"], call["weights"]) == (
        False,
        100,
        "ok",
        MODEL.sha256,
    )
    chat = next(r["body"] for r in requests(log) if r["path"] == "/v1/chat/completions")
    assert (chat["temperature"], chat["top_k"], chat["seed"], chat["max_tokens"]) == (0.0, 1, 0, 64)
    assert chat["response_format"] == {"type": "json_schema", "json_schema": {"name": "output", "schema": SCHEMA}}
    assert (boxes[0].ups, boxes[0].downs) == (1, 1)


def test_a_rejected_answer_is_retried_once_with_its_problems(tmp_path, workspace, server):
    argv, log = server("this is not JSON", answer())
    service, _, _ = make_service(tmp_path, workspace, argv)
    (result,) = run_tasks(service, task())
    assert (result.status, result.calls) == ("answered", 2)
    chats = [r["body"] for r in requests(log) if r["path"] == "/v1/chat/completions"]
    assert "the answer is not valid JSON" in chats[1]["messages"][-1]["content"]


def test_a_task_ends_invalid_when_the_retry_fails_and_no_other_route_exists(tmp_path, workspace, server):
    argv, _ = server(answer(), answer())
    service, _, _ = make_service(tmp_path, workspace, argv)
    (result,) = run_tasks(service, task(check=lambda output: ["cites E9, which is not in the task"]))
    assert (result.status, result.calls) == ("invalid", 2)
    assert result.reason == "model_output_invalid: cites E9, which is not in the task"


def test_a_decline_is_reported_never_rewritten(tmp_path, workspace, server):
    argv, _ = server(answer(status="cannot_answer", reason="insufficient_evidence"))
    service, _, _ = make_service(tmp_path, workspace, argv)
    (result,) = run_tasks(service, task())
    assert (result.status, result.reason, result.output) == ("declined", "model_declined:insufficient_evidence", None)


def test_a_warm_rerun_makes_no_model_calls(tmp_path, workspace, server):
    argv, _ = server("this is not JSON", answer())
    first, _, _ = make_service(tmp_path, workspace, argv)
    run_tasks(first, task())
    argv, _ = server()  # the stand-in has nothing left to say
    again, run, boxes = make_service(tmp_path, workspace, argv)
    (result,) = run_tasks(again, task())
    assert (result.status, result.calls, result.cache_hits) == ("answered", 0, 2)  # both attempts replay from cache
    assert boxes == []  # no model was even started
    assert [e["cache_hit"] for e in events(run) if e["type"] == "model.call"] == [True, True]


def test_budgets_and_context_limits_stop_a_task_before_the_call(tmp_path, workspace, server):
    argv, log = server(answer())
    service, _, _ = make_service(tmp_path, workspace, argv, budget=50)
    (result,) = run_tasks(service, task())
    assert (result.status, result.reason) == ("budget", "the run's model token budget is exhausted")
    service, _, _ = make_service(tmp_path, workspace, argv, profile=TINY_CONTEXT)
    (result,) = run_tasks(service, task())
    assert result.status == "budget"
    assert result.reason.endswith("the context holds 64")
    assert not any(r["path"] == "/v1/chat/completions" for r in requests(log))


def test_an_unconfigured_route_is_unavailable(tmp_path, workspace, server):
    argv, _ = server()
    service, _, boxes = make_service(tmp_path, workspace, argv, choices={})
    (result,) = run_tasks(service, task())
    assert result.status == "unavailable"
    assert "veritas models route analysis" in result.reason
    assert boxes == []
