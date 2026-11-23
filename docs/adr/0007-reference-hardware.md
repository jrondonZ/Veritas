# 0007. Make the development laptop the Phase 2 reference machine

- Status: Accepted
- Date: 2026-11-19

## Context

Open question Q3 asked which machine Phase 2's default models and its 15-minute budget for model-on runs should target. The design's smallest profile, `cpu`, assumes 8 cores and 32 GB of RAM. The machine Veritas is developed and evaluated on is smaller:

| | Reference machine |
|---|---|
| CPU | AMD Ryzen 5 PRO 8540U, 6 cores / 12 threads (Zen 4, AVX-512) |
| RAM | 15 GB, of which Docker Desktop's VM gets 7.6 GB |
| GPU | Radeon 740M integrated. Docker Desktop on Windows passes through only NVIDIA GPUs, so the model server runs on the CPU. |

A 30B mixture-of-experts model for the `analysis` route needs about 18 GB at 4-bit, which this machine can't hold. Targeting a larger machine would mean the model-on eval and the time budget couldn't be measured where Veritas is built.

## Decision

- **Add a profile.** A new `laptop` profile has 6 or more cores, about 16 GB of RAM, and no usable GPU. A single 3–4B instruct model at Q4_K_M, about 2.5 GB of weights, serves `triage` and `analysis`. The KV cache and buffers bring the server to roughly 4 GB.
- **Alias `deep` explicitly.** `deep` is aliased to the same model by explicit configuration. High and critical findings therefore get the mechanical claim linter and a `limitation` claim saying no deep review ran (§10.3).
- **Compare two candidates.** Both are permissively licensed: Qwen3-4B-Instruct-2507 (Apache-2.0) and Phi-4-mini-instruct (MIT). The operator downloads the GGUF files once. Veritas registers them by hash and never downloads weights. The Phase 2 routing eval compares them on the lab ground truth, and the profile's default comes from its documented result.
- **Budget for this machine.** The 15-minute budget for model-on runs is measured on this machine.

## Consequences

- Model work is sized for a small model. Prompts stay short and every output is schema-constrained. Every model step is optional, so finding status never depends on the model.
- Tailored guidance and patch drafts should work. A 4B model is a weak reviewer, though, and the report says so whenever no deep review ran.
- The `cpu`, `gpu-12`, and `gpu-24` profiles stay in the design. They become usable once someone measures them with `veritas models doctor` and the routing eval on matching hardware.
