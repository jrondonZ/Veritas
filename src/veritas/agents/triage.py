"""The triage role (docs/architecture.md §10.1): label each discovered route's sensitivity, once per run.

Labels are context for people reading the report. They never change planning, gating,
or a finding's status. The answer must label every route in the catalog exactly once.
"""

from __future__ import annotations

from typing import Any

from ..models.calls import ModelTask, answer_envelope
from ..models.prompts import Prompt, untrusted

VERSION = "1"
SENSITIVITY = ("public", "user-data", "account", "admin")
SYSTEM = """\
You are triage. You get the routes Veritas found on the target. Give each route exactly one sensitivity:
- "public": no sign-in needed and no user data;
- "user-data": reads or changes one user's own data;
- "account": credentials, sessions, profiles, or roles;
- "admin": administration.
Add a note of at most a few words only when the path alone doesn't make the route's purpose clear.
"""


def task(routes: list[dict[str, Any]]) -> ModelTask:
    labels = [r["label"] for r in routes]
    catalog = "\n".join(f"- {r['label']}{' (sign-in required)' if r['auth'] else ''}" for r in routes)
    schema = answer_envelope(
        {
            "labels": {
                "type": "array",
                "maxItems": len(labels),
                "items": {
                    "type": "object",
                    "properties": {
                        "route": {"type": "string", "enum": labels},
                        "sensitivity": {"type": "string", "enum": list(SENSITIVITY)},
                        "note": {"type": "string", "maxLength": 80},
                    },
                    "required": ["route", "sensitivity", "note"],
                    "additionalProperties": False,
                },
            }
        },
        ["labels"],
    )

    def check(output: dict[str, Any]) -> list[str]:
        given = [item["route"] for item in output["labels"]]
        problems = [f"{r} is labeled more than once" for r in sorted({r for r in given if given.count(r) > 1})]
        return problems + [f"{r} has no label" for r in labels if r not in given]

    prompt = Prompt("triage", VERSION, SYSTEM, "Label these routes.", untrusted(catalog, "target"))
    return ModelTask("triage", "triage", "routes", prompt, schema, 60 + 30 * len(labels), check)


def apply(output: dict[str, Any], producer: str) -> dict[str, Any]:
    return {
        "producer": producer,
        "routes": {
            item["route"]: {"sensitivity": item["sensitivity"], "note": item["note"].strip()}
            for item in sorted(output["labels"], key=lambda i: i["route"])
        },
    }
