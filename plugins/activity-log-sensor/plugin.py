"""Veritas activity-log sensor plugin (stdlib only).

Reads an owned app's activity log from a read-only mount, with no network access
(docs/architecture.md §6.1 and §9.4): the files it opens, the processes it starts, and
the outbound requests it makes. `mark` returns the log's current end. `collect` returns
the entries written since a mark that mention one of the kernel's canaries. The kernel's
oracle decides what they mean; this plugin only selects.

Each log line is a JSON object with a `kind`. Entries keep only the fields their kind
defines, so equal behavior yields equal evidence across runs:

- file: `op` and `path`
- exec: `shell`, and either `command` (a shell command line) or `file` and `args`
- request: `method` and `url`
"""

from __future__ import annotations

import json
import os
import re
import sys

PROTOCOL_VERSION = "2025-06-18"
LOG = os.environ.get("VERITAS_ACTIVITY_LOG", "/inputs/app-logs/activity.jsonl")
MAX_SCAN = 64 * 1024 * 1024  # bytes read per collect
MAX_TEXT = 16 * 1024  # longer fields mark the entry malformed rather than truncated
MAX_ARGS = 64
MARKER = re.compile(r"^[A-Za-z0-9-]{8,64}$")

TOOLS = [
    {
        "name": "mark",
        "description": "Return the current end of the activity log.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        "outputSchema": {"type": "object", "properties": {"offset": {"type": "integer"}}, "required": ["offset"]},
    },
    {
        "name": "collect",
        "description": "Return activity entries written since a mark that mention any of the markers.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "since": {"type": "integer", "minimum": 0},
                "markers": {
                    "type": "array",
                    "items": {"type": "string", "pattern": MARKER.pattern},
                    "minItems": 1,
                    "maxItems": 16,
                },
                "max_entries": {"type": "integer", "minimum": 1, "maximum": 200},
            },
            "required": ["since", "markers"],
            "additionalProperties": False,
        },
        "outputSchema": {
            "type": "object",
            "properties": {
                "entries": {"type": "array", "items": {"type": "object"}},
                "scanned": {"type": "integer"},
                "malformed": {"type": "integer"},
                "truncated": {"type": "boolean"},
                "restarted": {"type": "boolean"},
                "offset": {"type": "integer"},
            },
            "required": ["entries", "scanned", "malformed", "truncated", "restarted", "offset"],
        },
    },
]


def _text(value: object) -> bool:
    return isinstance(value, str) and len(value) <= MAX_TEXT


def keep(entry: object) -> dict | None:
    """The fields an entry's kind defines, or None if it's malformed."""
    if not isinstance(entry, dict):
        return None
    kind = entry.get("kind")
    if kind == "file" and _text(entry.get("op")) and _text(entry.get("path")):
        return {"kind": "file", "op": entry["op"], "path": entry["path"]}
    if kind == "request" and _text(entry.get("method")) and _text(entry.get("url")):
        return {"kind": "request", "method": entry["method"], "url": entry["url"]}
    if kind == "exec" and entry.get("shell") is True and _text(entry.get("command")):
        return {"kind": "exec", "shell": True, "command": entry["command"]}
    if kind == "exec" and entry.get("shell") is False and _text(entry.get("file")):
        args = entry.get("args")
        if isinstance(args, list) and len(args) <= MAX_ARGS and all(_text(a) for a in args):
            return {"kind": "exec", "shell": False, "file": entry["file"], "args": args}
    return None


def _size() -> int:
    try:
        return os.path.getsize(LOG)
    except OSError:
        return 0  # nothing has been logged yet


def mark() -> dict:
    return {"offset": _size()}


def collect(since: int, markers: list[str], max_entries: int = 100) -> dict:
    if not markers or not all(isinstance(m, str) and MARKER.match(m) for m in markers):
        raise ValueError("markers must be 8 to 64 letters, digits, or hyphens")
    size = _size()
    restarted = since > size  # the log was emptied (a lab reset) after the mark
    start = 0 if restarted else since
    data = b""
    if size > start:
        with open(LOG, "rb") as f:
            f.seek(start)
            data = f.read(min(size - start, MAX_SCAN))
    complete = data[: data.rfind(b"\n") + 1]  # a line still being written is left for the next collect
    entries, scanned, malformed = [], 0, 0
    for raw in complete.splitlines():
        scanned += 1
        try:
            entry = keep(json.loads(raw))
        except ValueError:
            entry = None
        if entry is None:
            malformed += 1
            continue
        text = json.dumps(entry, ensure_ascii=False)
        if any(m in text for m in markers):
            entries.append(entry)
    return {
        "entries": entries[:max_entries],
        "scanned": scanned,
        "malformed": malformed,
        "truncated": len(entries) > max_entries or size - start > MAX_SCAN,
        "restarted": restarted,
        "offset": start + len(complete),
    }


def _reply(msg_id, result=None, error=None) -> None:
    msg = {"jsonrpc": "2.0", "id": msg_id}
    msg.update({"error": error} if error else {"result": result})
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def _call(name: str, args: dict) -> dict:
    if name == "mark":
        return mark()
    if name == "collect":
        return collect(int(args["since"]), list(args["markers"]), int(args.get("max_entries", 100)))
    raise KeyError(name)


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
                            "serverInfo": {"name": "veritas-activity-log-sensor", "version": "0.0.1"}})  # fmt: skip
        elif method == "tools/list":
            _reply(msg_id, {"tools": TOOLS})
        elif method == "tools/call" and msg["params"]["name"] in ("mark", "collect"):
            try:
                result = _call(msg["params"]["name"], msg["params"].get("arguments") or {})
            except (KeyError, TypeError, ValueError) as exc:
                _reply(msg_id, {"content": [{"type": "text", "text": str(exc)}], "structuredContent": {},
                                "isError": True})  # fmt: skip
                continue
            _reply(msg_id, {"content": [{"type": "text", "text": json.dumps(result)}],
                            "structuredContent": result, "isError": False})  # fmt: skip
        else:
            _reply(msg_id, error={"code": -32601, "message": f"method not found: {method}"})


if __name__ == "__main__":
    main()
