"""Architecture rules, checked statically over the source tree (docs/architecture.md §3, P9).

- `veritas.core` uses only the standard library and pydantic: it ships in the gateway image.
- `veritas.gateway` uses only `veritas.core`, pydantic, and h11: the image contains nothing else.
- Only `veritas.cli` imports typer, and no other package imports `veritas.cli`.
- No module imports a network client or a hosted-model SDK (no third-party services at run time).
- Third-party imports match the dependencies declared in pyproject.toml.
"""

import ast
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "src"
FORBIDDEN = ("requests", "httpx", "aiohttp", "urllib3", "urllib.request", "http.client", "xmlrpc", "smtplib",
             "ftplib", "anthropic", "openai", "boto3", "botocore", "google")  # fmt: skip
DECLARED = {"pydantic", "yaml", "typer", "h11"}  # import names of the pyproject dependencies


def module_name(path: Path) -> str:
    parts = list(path.relative_to(SRC).with_suffix("").parts)
    return ".".join(parts[:-1] if parts[-1] == "__init__" else parts)


def imported_names(path: Path) -> set[str]:
    """Absolute names of everything a module imports, with relative imports resolved."""
    mod = module_name(path)
    package = mod if path.name == "__init__.py" else mod.rpartition(".")[0]
    names: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0:
                names.add(node.module or "")
                continue
            base = package.split(".")[: len(package.split(".")) - (node.level - 1)]
            prefix = ".".join(base)
            if node.module:
                names.add(f"{prefix}.{node.module}")
            else:
                names.update(f"{prefix}.{alias.name}" for alias in node.names)
    return names


MODULES = {module_name(p): imported_names(p) for p in sorted(SRC.rglob("*.py"))}


def within(name: str, package: str) -> bool:
    return name == package or name.startswith(package + ".")


def top(name: str) -> str:
    return name.split(".")[0]


def third_party(names: set[str]) -> set[str]:
    return {top(n) for n in names if top(n) not in sys.stdlib_module_names and top(n) != "veritas"}


def modules_in(package: str) -> list[str]:
    return sorted(m for m in MODULES if within(m, package))


@pytest.mark.parametrize("module", modules_in("veritas.core"))
def test_core_uses_only_stdlib_and_pydantic(module):
    names = MODULES[module]
    assert third_party(names) <= {"pydantic"}
    assert all(within(n, "veritas.core") for n in names if top(n) == "veritas")


@pytest.mark.parametrize("module", modules_in("veritas.gateway"))
def test_gateway_uses_only_core(module):
    names = MODULES[module]
    assert third_party(names) <= {"pydantic", "h11"}
    internal = [n for n in names if top(n) == "veritas"]
    assert all(within(n, "veritas.core") or within(n, "veritas.gateway") for n in internal), internal


def test_only_the_cli_imports_typer():
    offenders = [m for m, names in MODULES.items() if "typer" in third_party(names) and not within(m, "veritas.cli")]
    assert offenders == []


def test_nothing_imports_the_cli():
    allowed = ("veritas.cli", "veritas.__main__")
    importers = [m for m, names in MODULES.items() if any(within(n, "veritas.cli") for n in names)]
    assert [m for m in importers if not any(within(m, a) for a in allowed)] == []


def test_no_network_or_hosted_model_clients():
    offenders = {m: sorted(n for n in names if any(within(n, f) for f in FORBIDDEN)) for m, names in MODULES.items()}
    assert {m: v for m, v in offenders.items() if v} == {}


def test_third_party_imports_match_declared_dependencies():
    used = set().union(*(third_party(names) for names in MODULES.values()))
    assert used == DECLARED
