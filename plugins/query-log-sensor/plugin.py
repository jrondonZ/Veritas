"""Veritas query-log sensor plugin (stdlib only).

Reads an owned app's SQL statement log from a read-only mount, with no network access
(docs/architecture.md §6.1 and §9.4). `mark` returns the log's current end. `collect`
returns, verbatim, the entries written since a mark that mention one of the kernel's
canaries. The kernel's oracle decides what they mean; this plugin only selects.

Each log line is a JSON object with the statement text in `sql` and its bound
parameters in `params`. Entries keep only those two fields, so equal behavior yields
equal evidence across runs.
"""

from __future__ import annotations

import json
import os
import re
import sys

PROTOCOL_VERSION = "2025-06-18"
LOG = os.environ.get("VERITAS_QUERY_LOG", "/inputs/query-log/queries.jsonl")
MAX_SCAN = 64 * 1024 * 1024  # bytes read per collect
MAX_SQL = 16 * 1024  # longer statements are reported as malformed, not truncated
MARKER = re.compile(r"^[A-Za-z0-9-]{8,64}$")

TOOLS = [
    {
        "name": "mark",
        "description": "Return the current end of the query log.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        "outputSchema": {
            "type": "object",
            "properties": {"offset": {"type": "integer"}},
            "required": ["offset"],
        },
    },
    {
        "name": "collect",
        "description": "Return log entries written since a mark that mention any of the markers.",
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
            entry = json.loads(raw)
        except ValueError:
            malformed += 1
            continue
        sql, params = (entry.get("sql"), entry.get("params")) if isinstance(entry, dict) else (None, None)
        if not isinstance(sql, str) or not isinstance(params, list) or len(sql) > MAX_SQL:
            malformed += 1
            continue
        bound = json.dumps(params, ensure_ascii=False)
        if any(m in sql or m in bound for m in markers):
            entries.append({"sql": sql, "params": params})
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
                            "serverInfo": {"name": "veritas-query-log-sensor", "version": "0.0.1"}})  # fmt: skip
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
