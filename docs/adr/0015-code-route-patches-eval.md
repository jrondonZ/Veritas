# 0015. A small coding model for clean-room code, model-drafted patches checked by the rules, and a routing eval

- Status: Accepted
- Date: 2026-11-21

## Context

Phase 2 left three model features unfinished: patch drafts for human review (the brief asks for them), the routing eval that picks a model per route, and the models-on acceptance run. On the reference laptop, a 4B general model is slow at writing whole modules. A 1 to 2B coding model is about 1 GB and much faster per round. But a small model's patch can't be trusted on its word, and neither can the claim that one model is better than another.

## Decision

- **A `code` route for implementations and patches.** The implementer and the new patcher use it. On the laptop profile it's aliased to `analysis` until the workspace chooses a model (`veritas models route code <name>`). A task the small model fails twice moves up to `analysis`. A small model gets an 8K context in the same memory, because its KV cache is a fraction of a 4B model's. The suggested model is Qwen2.5-Coder-1.5B-Instruct (Apache-2.0, about 1.1 GB at Q4_K_M), which the operator downloads; Veritas never fetches weights.
- **A patch is edits checked by the same rules.** The patcher sees one code finding with its rule's remediation, and the owned source file it's in. It answers with exact edits, each naming text that occurs once in the file. The kernel applies them to a copy, never to the operator's tree, and writes a unified diff. Then it reads the copy with the same engine and rules. The draft is verified only if:
  - the copy still parses;
  - the finding's rule no longer fires in that function;
  - no rule fires that didn't before.

  A person reviews the diff and applies it with their own tools. Patches are offered only for code whose charter basis is `owned`, and only for JavaScript in this phase.
- **The routing eval scores answers, not impressions.** `veritas models eval` runs each registered model on cases with known good answers:
  - **triage:** a route catalog, scored against an answer key;
  - **analysis:** a reflected-HTML finding's guidance, scored on validity and on naming the route and the parameter;
  - **code:** the lexfmt reader, scored by the conformance vectors it passes.

  It records latency and tokens, and recommends the best model per route, with a tie going to the faster one. The code case runs only against a lexfmt spec a person has already approved, because an eval doesn't bypass the clean-room gate. `--apply` saves the recommendation, and nothing else changes.
- **Models-on acceptance is a test with two claims.** Turning models on changes no finding's status, and every model claim passes the linter. A running model container has only a loopback interface and can't open a socket out. Both tests skip until weights are registered, and they never register weights or choose routes themselves.

## Consequences

- Clean-room drafts and patches can run on about 1 GB of weights, with the 4B model as the fallback.
- A patch Veritas calls verified is proven to remove the finding and add nothing the rules can see. That's narrower than "correct", so review stays mandatory.
- The eval's cases are small, so its recommendation fits this lab and this machine. More cases will make it a better general guide.
