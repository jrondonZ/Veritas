#!/bin/bash
# Veritas model relay: the kernel's only way to reach llama-server, which listens on loopback inside a container that
# has no network at all (docs/architecture.md §6.6, ADR 0008). The kernel runs this once per model session with
# `docker exec -i`.
#
# Each request arrives on stdin as a decimal byte count on its own line, followed by exactly that many bytes of
# HTTP/1.1 with "Connection: close". The response goes to stdout as one line of base64. An empty line means the
# server is not accepting connections yet.
set -u
while IFS= read -r length; do
  case "$length" in
    '' | *[!0-9]*) echo "relay: bad frame" >&2; exit 2 ;;
  esac
  # Read the whole request before connecting, so a refused connection can't desynchronize the stream.
  request="$(head -c "$length" | base64 -w0)"
  ( exec 3<>/dev/tcp/127.0.0.1/8080 && { printf '%s' "$request" | base64 -d >&3; base64 -w0 <&3; } ) 2>/dev/null
  echo
done
