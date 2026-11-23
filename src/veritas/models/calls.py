"""The model-call contract (docs/architecture.md §10.3 to §10.6).

Every model step goes through `ModelService.run`, which:

- resolves the task's route to a registered model (aliases are explicit, never automatic);
- starts that model's sandbox on first use, one model at a time (§10.6);
- builds the messages from redacted inputs and looks them up in the response cache;
- counts prompt tokens with the model's own tokenizer, and refuses a task that doesn't fit
  the context window or the run's token budget (nothing is silently truncated);
- validates the output against its schema and the task's own checks (reference integrity);
- retries once with the problems appended, then once on the next configured route, then
  ends the task `invalid` (§10.3);
- records every attempt in the audit chain: route, model, weights, prompt hash, tokens,
  cache hit, and status.

A model never decides a finding's status. Its output is data that the caller checks.
"""

from __future__ import annotations

import asyncio
import json
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from typing import Any, Literal

from ..core.canonical import digest
from ..sandbox.model import ModelSandbox
from ..store import AuditChain
from .cache import ResponseCache
from .profiles import RouteUnavailable, Routing
from .prompts import Prompt
from .redact import redact
from .registry import RegisteredModel
from .schema import validate
from .server import LlamaCppServer, ModelServerError, RelayClient, Sampling

Status = Literal["answered", "declined", "invalid", "budget", "unavailable", "error"]
DECLINE_REASONS = ("insufficient_evidence", "outside_role", "conflicting_evidence", "other")
ESCALATE_REASONS = ("none", "insufficient_context", "conflicting_evidence", "complex_authorization_logic")
SAMPLING = Sampling()
MAX_ATTEMPTS = 3

Check = Callable[[dict[str, Any]], list[str]]
Log = Callable[[str, str], None]


def answer_envelope(answer: dict[str, Any], required: list[str]) -> dict[str, Any]:
    """Wrap a role's answer schema with the fields every role output carries (§10.3, §10.4)."""
    return {
        "type": "object",
        "properties": {
            "status": {"type": "string", "enum": ["answered", "cannot_answer"]},
            "reason": {"type": "string", "enum": ["none", *DECLINE_REASONS]},
            "escalate": {"type": "string", "enum": list(ESCALATE_REASONS)},
            **answer,
        },
        "required": ["status", "reason", "escalate", *required],
        "additionalProperties": False,
    }


@dataclass(frozen=True)
class ModelTask:
    role: str
    route: str
    subject: str  # what the task is about (a finding ID, for example), for the audit log
    prompt: Prompt
    schema: dict[str, Any]
    max_tokens: int
    check: Check = field(default=lambda output: [])  # semantic checks after the schema, e.g. reference integrity


@dataclass
class ModelResult:
    status: Status
    role: str
    reason: str = ""
    output: dict[str, Any] | None = None
    model: RegisteredModel | None = None
    serving: str | None = None  # the route that answered, after aliases
    aliased: bool = False
    calls: int = 0  # model calls made (cache hits excluded)
    cache_hits: int = 0
    tokens: int = 0

    @property
    def producer(self) -> str:
        """The `producer` of claims this result contributes: role, model name, and weight digest."""
        return f"{self.role}@{self.model.name}:{self.model.digest_short}" if self.model else self.role


class TokenBudget:
    def __init__(self, limit: int):
        self.limit, self.used = limit, 0

    def allows(self, tokens: int) -> bool:
        return self.used + tokens <= self.limit

    def charge(self, tokens: int) -> None:
        self.used += tokens


class ModelService:
    def __init__(
        self,
        routing: Routing,
        image: str,
        run_id: str,
        audit: AuditChain,
        cache: ResponseCache,
        budget: TokenBudget,
        *,
        redact_prompts: bool = True,
        log: Log = lambda label, text: None,
        sandbox_factory: Callable[[RegisteredModel], ModelSandbox] | None = None,
    ):
        self.routing, self.image, self.run_id = routing, image, run_id
        self.audit, self.cache, self.budget = audit, cache, budget
        self.redact_prompts, self.log = redact_prompts, log
        self._factory = sandbox_factory or self._sandbox
        self._active: tuple[str, ModelSandbox, RelayClient, LlamaCppServer] | None = None
        self.stats: Counter[str] = Counter()
        self.redactions: Counter[str] = Counter()

    def _sandbox(self, model: RegisteredModel) -> ModelSandbox:
        return ModelSandbox(self.run_id, self.image, model.file, self.routing.profile.limits_for(model), model.name)

    async def _server(self, model: RegisteredModel) -> LlamaCppServer:
        if self._active is not None and self._active[0] == model.name:
            return self._active[3]
        await self._stop()  # one model at a time, so memory for the next one is free (§10.6)
        sandbox = self._factory(model)
        started = time.monotonic()
        await asyncio.to_thread(sandbox.up)
        relay = RelayClient(sandbox.relay_argv())
        server = LlamaCppServer(relay)
        try:
            await server.wait_ready()
        except Exception as exc:
            tail = await asyncio.to_thread(sandbox.logs)
            await relay.close()
            await asyncio.to_thread(sandbox.down)
            raise ModelServerError(f"{model.name} did not become ready: {exc}; server log: {tail[-400:]}") from exc
        load = round(time.monotonic() - started, 1)
        self.audit.append(
            "model.start",
            model=model.name,
            weights=model.sha256,
            license=model.license,
            quantization=model.quantization,
            image=self.image,
            limits=asdict(self.routing.profile.limits_for(model)),
            load_s=load,
        )
        self.log("model", f"{model.name} loaded in {load} s · {model.quantization} · {model.license}")
        self._active = (model.name, sandbox, relay, server)
        return server

    async def _stop(self) -> None:
        if self._active is None:
            return
        name, sandbox, relay, _ = self._active
        self._active = None
        await relay.close()
        await asyncio.to_thread(sandbox.down)
        self.audit.append("model.stop", model=name)

    async def close(self) -> None:
        await self._stop()

    def _messages(self, task: ModelTask, feedback: list[str]) -> list[dict[str, str]]:
        messages = task.prompt.messages(feedback)
        if not self.redact_prompts:
            return messages
        out = []
        for message in messages:
            text, found = redact(message["content"])
            self.redactions.update(found)
            out.append({**message, "content": text})
        return out

    @staticmethod
    def _parse(task: ModelTask, text: str) -> tuple[dict[str, Any] | None, list[str]]:
        try:
            output = json.loads(text)
        except ValueError:
            return None, ["the answer is not valid JSON"]
        problems = validate(task.schema, output)
        if problems or not isinstance(output, dict):
            return None, problems or ["the answer is not a JSON object"]
        if output.get("status") == "answered":
            problems = task.check(output)
        return output, problems

    async def run(self, task: ModelTask) -> ModelResult:
        result = ModelResult("invalid", task.role)
        feedback: list[str] = []
        route, escalated = task.route, False
        for attempt in range(1, MAX_ATTEMPTS + 1):
            try:
                resolved = self.routing.resolve(route)
            except RouteUnavailable as exc:
                return self._end(task, result, "unavailable", str(exc))
            result.model, result.serving, result.aliased = resolved.model, resolved.serving, resolved.aliased
            messages = self._messages(task, feedback)
            key = ResponseCache.key(
                weights=resolved.model.sha256,
                runtime=self.image,
                sampling=SAMPLING.to_json(),
                template=f"{task.prompt.role}/{task.prompt.version}",
                schema=digest(task.schema),
                max_tokens=task.max_tokens,
                messages=messages,
            )
            cached = self.cache.get(key)
            prompt_tokens = completion_tokens = 0
            if cached is not None:
                text, hit = str(cached["text"]), True
                result.cache_hits += 1
            else:
                try:
                    server = await self._server(resolved.model)
                    needed = await server.count_tokens(messages) + task.max_tokens
                    context = self.routing.profile.limits_for(resolved.model).context
                    if needed > context:
                        return self._end(task, result, "budget", f"needs {needed} tokens; the context holds {context}")
                    if not self.budget.allows(needed):
                        return self._end(task, result, "budget", "the run's model token budget is exhausted")
                    generation = await server.generate(messages, task.schema, SAMPLING, task.max_tokens)
                except ModelServerError as exc:
                    return self._end(task, result, "error", f"{type(exc).__name__}: {exc}")
                prompt_tokens, completion_tokens = generation.prompt_tokens, generation.completion_tokens
                self.budget.charge(prompt_tokens + completion_tokens)
                result.calls += 1
                result.tokens += prompt_tokens + completion_tokens
                text, hit = generation.text, False
                self.cache.put(key, {"text": text, "finish_reason": generation.finish_reason,
                                     "prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens,
                                     "model": resolved.model.name, "weights": resolved.model.sha256})  # fmt: skip
            output, problems = self._parse(task, text)
            self.audit.append(
                "model.call",
                role=task.role,
                subject=task.subject,
                route=route,
                serving=resolved.serving,
                model=resolved.model.name,
                weights=resolved.model.sha256,
                prompt=digest(messages),
                attempt=attempt,
                cache_hit=hit,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                status="ok" if output is not None and not problems else "invalid",
                problems=problems[:5],
            )
            self.stats["calls" if not hit else "cache_hits"] += 1
            if output is not None and not problems:
                if output.get("status") == "cannot_answer":
                    return self._end(task, result, "declined", f"model_declined:{output.get('reason') or 'other'}")
                wants = output.get("escalate", "none")
                nxt = self.routing.escalate(route) if wants != "none" and not escalated else None
                if nxt is not None:  # §10.3: one move up the configured routes
                    route, feedback, escalated = nxt, [], True
                    continue
                result.output = output
                return self._end(task, result, "answered", "")
            feedback = problems
            if attempt == 2:  # the third attempt goes to the next configured route, if there is one
                nxt = self.routing.escalate(route)
                if nxt is None:
                    break
                route = nxt
        return self._end(task, result, "invalid", "model_output_invalid: " + "; ".join(feedback[:3]))

    def _end(self, task: ModelTask, result: ModelResult, status: Status, reason: str) -> ModelResult:
        result.status, result.reason = status, reason
        self.stats[status] += 1
        if status != "answered":
            self.log("model", f"{task.role} {task.subject}: {status} ({reason})")
        return result
