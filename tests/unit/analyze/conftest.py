import asyncio
import shutil
import sys

import pytest

from veritas.analyze.program import FileModel
from veritas.plugins.host import start_plugin
from veritas.plugins.manifest import load_manifest

NODE = shutil.which("node")
SUBJECT = "dist/lexfmt.js"


@pytest.fixture(scope="session")
def lexfmt(repo_root):
    return repo_root / "labs" / "lexfmt"


@pytest.fixture(scope="session")
def subject_sha(lexfmt):
    from veritas.core.canonical import sha256_hex

    return sha256_hex((lexfmt / SUBJECT).read_bytes())


def _run_engine(repo_root, inputs, files, engine="js-engine", argv=None):
    manifest = load_manifest(repo_root / "plugins" / engine / "veritas-plugin.yaml")

    async def main():
        command = argv or [NODE, str(repo_root / "plugins" / engine / "plugin.mjs")]
        session = await start_plugin(command, manifest, env={"VERITAS_INPUTS": str(inputs)})
        try:
            return (await session.call("analyze", {"files": files}))["results"]
        finally:
            await session.close()

    return asyncio.run(main())


@pytest.fixture(scope="session")
def node():
    if NODE is None:
        pytest.skip("Node.js is not installed")
    return NODE


@pytest.fixture(scope="session")
def run_engine(node, repo_root):
    """Run the JS engine plugin as a local process (no sandbox) and return its per-file results."""
    return lambda inputs, files: _run_engine(repo_root, inputs, files)


@pytest.fixture(scope="session")
def run_binary_engine(repo_root):
    """Run the binary engine plugin as a local Python process (no sandbox) and return its per-file results."""
    argv = [sys.executable, str(repo_root / "plugins" / "binary-engine" / "plugin.py")]
    return lambda inputs, files: _run_engine(repo_root, inputs, files, engine="binary-engine", argv=argv)


@pytest.fixture(scope="session")
def lexfmt_model(run_engine, lexfmt, subject_sha):
    (facts,) = run_engine(lexfmt, [{"path": SUBJECT, "sha256": subject_sha}])
    return FileModel(SUBJECT, subject_sha, "E-0123456789ab", facts)
