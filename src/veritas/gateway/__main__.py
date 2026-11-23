"""Gateway container entrypoint.

Environment: VERITAS_RUN_KEY (hex, required), VERITAS_IDENTITY_SECRETS (JSON object of
identity id -> login secret), VERITAS_GATEWAY_CONFIG (default /etc/veritas/gateway.json),
VERITAS_CAPTURE_DIR (default /capture). Both secrets are removed from the environment at start-up.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import signal
from pathlib import Path

from .admission import GatewayConfig
from .control import serve_control
from .proxy import CaptureSink, Gateway


async def _run(config: GatewayConfig, key: bytes, capture: Path, secrets: dict[str, str]) -> None:
    mask_key = hmac.new(key, b"veritas-mask-v1", hashlib.sha256).digest()
    sink = CaptureSink(capture, mask_key=mask_key)
    gateway = Gateway(config, key, sink, secrets=secrets)
    proxy = await gateway.serve("0.0.0.0", 8080)  # noqa: S104 - container-internal; its networks are internal-only
    control = await serve_control(gateway)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    print("veritas-gateway ready", flush=True)
    await stop.wait()
    gateway.revoke(everything=True)
    proxy.close()
    control.close()
    sink.close()


def main() -> None:
    config_path = Path(os.environ.get("VERITAS_GATEWAY_CONFIG", "/etc/veritas/gateway.json"))
    config = GatewayConfig.model_validate_json(config_path.read_text(encoding="utf-8"))
    key = bytes.fromhex(os.environ.pop("VERITAS_RUN_KEY"))
    secrets = json.loads(os.environ.pop("VERITAS_IDENTITY_SECRETS", "{}"))
    asyncio.run(_run(config, key, Path(os.environ.get("VERITAS_CAPTURE_DIR", "/capture")), secrets))


if __name__ == "__main__":
    main()
