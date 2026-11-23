"""Veritas binary engine plugin: the MCP-compatible stdio loop around binfmt and dotnet (stdlib only).

It runs in the `engine` sandbox: no network, inputs mounted read-only. Each file is hashed
while it streams, then memory-mapped, so a large binary is never copied into memory whole.
Nothing in it is executed, and only a parse error, never a crash, comes from hostile input.
"""

from __future__ import annotations

import hashlib
import json
import mmap
import os
import struct
import sys
from pathlib import PurePosixPath
from typing import Any

# The image runs Python isolated (-I), which leaves the script's own directory off the import path.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import binfmt
import dotnet

VERSION = "0.0.1"
PROTOCOL_VERSION = "2025-06-18"
INPUTS = os.environ.get("VERITAS_INPUTS", "/inputs")
MAX_SUBJECT = 256 * 1024 * 1024  # the charter's limit
TOOLS = [
    {
        "name": "analyze",
        "description": "Read PE, ELF, and Mach-O files (and .NET metadata) from the read-only inputs and return "
        "their Program Model facts.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "files": {
                    "type": "array",
                    "maxItems": 200,
                    "items": {
                        "type": "object",
                        "properties": {"path": {"type": "string"}, "sha256": {"type": "string"}},
                        "required": ["path", "sha256"],
                        "additionalProperties": False,
                    },
                },
            },
            "required": ["files"],
            "additionalProperties": False,
        },
        "outputSchema": {"type": "object", "properties": {"results": {"type": "array"}}, "required": ["results"]},
    }
]


def input_path(relative: str) -> str:
    parts = PurePosixPath(relative.replace("\\", "/")).parts
    if not relative or relative.startswith(("/", "\\")) or ":" in relative or ".." in parts:
        raise ValueError(f"refused input path {relative!r}")
    return os.path.join(INPUTS, *parts)


def merge_managed(facts: dict[str, Any]) -> dict[str, Any]:
    """A .NET assembly's literals, names, and patterns come from its metadata, not the PE's raw bytes."""
    managed = facts.get("dotnet")
    if not managed:
        return facts
    facts["strings"] = managed.pop("strings")
    facts["withheld"] += managed.pop("withheld")
    facts["identifiers"] = managed.pop("identifiers")
    facts["exports"] = managed.pop("exports") + facts["exports"]
    facts["sinks"] = managed.pop("sinks")
    facts["crypto"] = facts["crypto"] + managed.pop("crypto")
    facts["imports"] = facts["imports"] + [{**p, "pinvoke": True} for p in managed["pinvoke"]]
    return binfmt.summarize(facts)


def analyze_file(file: dict[str, Any]) -> dict[str, Any]:
    path = input_path(file["path"])
    with open(path, "rb") as fh:
        size = os.fstat(fh.fileno()).st_size
        if size > MAX_SUBJECT:
            return {"path": file["path"], "error": f"larger than {MAX_SUBJECT} bytes"}
        digest = hashlib.sha256()
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
        sha256 = digest.hexdigest()
        if file.get("sha256") and file["sha256"] != sha256:
            return {"path": file["path"], "sha256": sha256, "error": "content does not match the pinned sha256"}
        if size == 0:
            return {"path": file["path"], "sha256": sha256, "error": "the file is empty"}
        with mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as data:
            try:
                facts = merge_managed(binfmt.analyze(data, dotnet.read))
            except binfmt.FormatError as exc:
                return {"path": file["path"], "sha256": sha256, "error": f"not read: {exc}"}
            except (struct.error, IndexError, KeyError, ValueError, RecursionError, UnicodeError) as exc:
                return {"path": file["path"], "sha256": sha256,
                        "error": f"analysis failed: {type(exc).__name__}: {str(exc)[:200]}"}  # fmt: skip
    facts.setdefault("sinks", [])
    return {"path": file["path"], "sha256": sha256, "bytes": size, "engine": f"veritas.engine.binary@{VERSION}",
            **facts}  # fmt: skip


def _reply(msg_id: Any, result: Any = None, error: Any = None) -> None:
    msg = {"jsonrpc": "2.0", "id": msg_id}
    msg.update({"error": error} if error else {"result": result})
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def main() -> None:
    for line in sys.stdin:
        if not line.strip():
            continue
        msg = json.loads(line)
        method, msg_id = msg.get("method"), msg.get("id")
        if msg_id is None:
            continue  # notifications need no reply
        if method == "initialize":
            _reply(msg_id, {"protocolVersion": PROTOCOL_VERSION, "capabilities": {"tools": {}},
                            "serverInfo": {"name": "veritas-binary-engine", "version": VERSION}})  # fmt: skip
        elif method == "tools/list":
            _reply(msg_id, {"tools": TOOLS})
        elif method == "tools/call" and msg["params"].get("name") == "analyze":
            results = []
            for file in (msg["params"].get("arguments") or {}).get("files", []):
                try:
                    results.append(analyze_file(file))
                except (OSError, ValueError) as exc:
                    results.append({"path": file.get("path"), "error": str(exc)[:200]})
            _reply(msg_id, {"content": [{"type": "text", "text": f"{len(results)} files"}],
                            "structuredContent": {"results": results}, "isError": False})  # fmt: skip
        else:
            _reply(msg_id, error={"code": -32601, "message": f"method not found: {method}"})


if __name__ == "__main__":
    main()
