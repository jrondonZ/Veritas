"""The implementer role (docs/architecture.md §10.1, §8.3 step 7): a clean-room implementation from the approved spec.

Its prompt is built only from clean inputs: the approved spec's claims and the
operator-owned conformance vectors, with their sample bytes. It never sees the subject,
the Program Model, the draft spec, or a similarity result. The kernel checks the module
mechanically (it exports the vectors' function and uses no imports, I/O, network, or
dynamic code), and then the conformance harness decides whether it works.
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from typing import Any

from ..models.calls import ModelTask, answer_envelope
from ..models.prompts import Prompt, untrusted

VERSION = "1"
MAX_MODULE = 16000
MAX_SAMPLE_BYTES = 256
FORBIDDEN = re.compile(
    r"\bimport\b|\brequire\s*\(|\bprocess\b|\bfetch\s*\(|\beval\s*\(|\bnew\s+Function\b|\bglobalThis\b|"
    r"XMLHttpRequest|WebSocket|\bDeno\b|\bBun\b"
)
SYSTEM = """\
You are the implementer in a clean room. You get an approved behavior spec and conformance vectors: each sample's \
bytes in hex and the result expected from reading it. Write one self-contained JavaScript ES module that exports \
the function the task names. It takes a Uint8Array. It returns the expected value, or throws an Error whose \
`code` property is the expected error code.
- Use only the spec and the vectors. Where the spec says something is unknown or excluded, do the least the \
vectors require.
- No imports, no I/O, no network, no dynamic code. Plain modern JavaScript.
- Return plain objects, arrays, numbers, and strings, shaped exactly like the expected values.
"""


def spec_text(clean: dict[str, Any]) -> str:
    lines = []
    for interface in clean["interfaces"]:
        lines.append(f"{interface['id']} {interface['title']}:")
        lines += [f"- ({c['kind']}) {c['text']}" for c in interface["claims"]]
    return "\n".join(lines)


def vectors_text(clean: dict[str, Any], samples: dict[str, bytes]) -> str:
    lines = []
    for vector in clean["conformance"]["vectors"]:
        data = samples[vector["sample"]]
        hexed = data[:MAX_SAMPLE_BYTES].hex(" ")
        cut = f" … ({len(data)} bytes)" if len(data) > MAX_SAMPLE_BYTES else f" ({len(data)} bytes)"
        expect = json.dumps(vector["expect"], sort_keys=True)
        lines.append(f"{vector['id']}: bytes {hexed}{cut}\n  expect {expect[:700]}")
    return "\n".join(lines)


def task(clean: dict[str, Any], samples: dict[str, bytes], failures: Sequence[str] = ()) -> ModelTask:
    call = clean["conformance"]["call"]
    schema = answer_envelope(
        {"module": {"type": "string", "maxLength": MAX_MODULE}, "notes": {"type": "string", "maxLength": 400}},
        ["module", "notes"],
    )
    data = f"Export: {call}(bytes)\n\nConformance vectors:\n" + untrusted(
        vectors_text(clean, samples), "operator vectors"
    )
    if failures:
        data += "\n\nYour previous module failed these vectors:\n" + "\n".join(f"- {f}" for f in failures)

    def check(output: dict[str, Any]) -> list[str]:
        module = output["module"]
        problems = []
        if not re.search(rf"export\s+(async\s+)?function\s+{re.escape(call)}\b|export\s*\{{[^}}]*\b{re.escape(call)}\b",
                         module):  # fmt: skip
            problems.append(f"the module must export a function named {call}")
        if bad := sorted(set(FORBIDDEN.findall(module))):
            problems.append(f"the module uses what the clean room forbids: {', '.join(bad)}")
        return problems

    prompt = Prompt("implementer", VERSION, SYSTEM, untrusted(spec_text(clean), "approved spec"), data)
    # The code route: a small coding model if the workspace chose one, otherwise whatever serves `analysis`.
    return ModelTask("implementer", "code", "cleanroom", prompt, schema, 2500, check)
