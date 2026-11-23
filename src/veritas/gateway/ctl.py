"""Gateway control client, run inside the gateway container via docker exec.

    python -m veritas.gateway.ctl revoke --tid T | revoke --all | stats | health
    python -m veritas.gateway.ctl stdio    # relay JSON lines from stdin; one reply line each

The kernel keeps one `stdio` relay open per run, so a revocation costs a pipe
write instead of a `docker exec` start-up (seconds on some Docker Desktop hosts).
"""

from __future__ import annotations

import argparse
import json
import sys

from .control import call


def main() -> int:
    parser = argparse.ArgumentParser(prog="veritas.gateway.ctl")
    sub = parser.add_subparsers(dest="op", required=True)
    revoke = sub.add_parser("revoke")
    group = revoke.add_mutually_exclusive_group(required=True)
    group.add_argument("--tid")
    group.add_argument("--all", action="store_true")
    sub.add_parser("stats")
    sub.add_parser("health")
    sub.add_parser("stdio")
    args = parser.parse_args()
    if args.op == "stdio":
        for line in sys.stdin:
            if not line.strip():
                continue
            try:
                reply = call(json.loads(line))
            except Exception as exc:  # keep relaying; report the failure as a reply
                reply = {"ok": False, "error": str(exc)}
            sys.stdout.write(json.dumps(reply) + "\n")
            sys.stdout.flush()
        return 0
    msg = {"op": args.op}
    if args.op == "revoke":
        msg.update(tid=args.tid, all=args.all)
    reply = call(msg)
    print(json.dumps(reply))
    return 0 if reply.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
