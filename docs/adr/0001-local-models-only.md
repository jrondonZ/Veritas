# 0001. Run models locally only; no hosted model APIs

- Status: Accepted
- Date: 2026-11-18

## Context

The first draft of the architecture routed model tasks to a hosted model API. The project owner then set a requirement: Veritas must not depend on a third-party API. Veritas also handles target responses and decompiled code, which should not leave the operator's machine.

## Decision

- Models run only on the operator's hardware. The default is llama.cpp's `llama-server` in a container with no network egress, reached over loopback. Ollama and vLLM fit behind the same adapter.
- Veritas ships no adapter for hosted model APIs.
- Weights are registered from local files and pinned by SHA-256. Veritas never downloads them.
- Finding status never depends on a model. With models switched off, the pipeline still produces complete, confirmed findings, because every check ships a default CVSS vector and a remediation template.

## Consequences

- Model quality and speed depend on local hardware. Routes are configured per hardware profile, and Phase 2 sets the defaults from an eval over the lab's ground truth.
- Structured output relies on schema-constrained decoding in the local server.
- Replays are reproducible because the response cache is keyed by weight digest, runtime version, and prompt.
- `tests/unit/test_architecture.py` fails if any module imports an HTTP client or a hosted-model SDK.
