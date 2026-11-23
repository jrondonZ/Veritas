"""A stand-in for the model container's relay and llama-server, for unit tests.

It speaks the relay's framing on stdio (a byte count line, then raw HTTP; one line of
base64 back). Chat completion answers come, in order, from the JSON list in
$FAKE_ANSWERS_FILE. Every request is appended to $FAKE_LOG as one JSON line.
"""

import base64
import json
import os
import sys

with open(os.environ["FAKE_ANSWERS_FILE"], encoding="utf-8") as f:
    answers = json.load(f)
log_path = os.environ["FAKE_LOG"]
loading = int(os.environ.get("FAKE_LOADING", "0"))  # /health answers 503 this many times first
refuse = int(os.environ.get("FAKE_REFUSE", "0"))  # the first requests find no listener: the relay prints ""
out, stdin = sys.stdout.buffer, sys.stdin.buffer


def respond(status, payload):
    body = json.dumps(payload).encode()
    head = f"HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n".encode()
    out.write(base64.b64encode(head + body) + b"\n")
    out.flush()


while line := stdin.readline():
    raw = stdin.read(int(line))
    head, _, body = raw.partition(b"\r\n\r\n")
    method, path, _ = head.split(b"\r\n")[0].decode().split(" ")
    request = json.loads(body) if body else None
    with open(log_path, "a", encoding="utf-8") as log:
        log.write(json.dumps({"method": method, "path": path, "body": request}) + "\n")
    if refuse > 0:
        refuse -= 1
        out.write(b"\n")
        out.flush()
    elif path == "/health":
        loading -= 1
        respond(503 if loading >= 0 else 200, {"status": "loading" if loading >= 0 else "ok"})
    elif path == "/apply-template":
        respond(200, {"prompt": "".join(m["content"] for m in request["messages"])})
    elif path == "/tokenize":
        respond(200, {"tokens": list(range(len(request["content"]) // 4))})
    elif path == "/v1/chat/completions":
        answer = answers.pop(0)
        content = answer if isinstance(answer, str) else json.dumps(answer)
        respond(200, {"choices": [{"message": {"content": content}, "finish_reason": "stop"}],
                      "usage": {"prompt_tokens": 100, "completion_tokens": 20},
                      "timings": {"prompt_ms": 50.0, "predicted_ms": 100.0}})  # fmt: skip
    else:
        respond(404, {"error": "not found"})
