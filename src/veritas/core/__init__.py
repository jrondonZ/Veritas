"""Pure kernel primitives: canonical JSON, impact classes, network policy, capability tokens.

This package depends only on the standard library and pydantic. The gateway image
ships it together with `veritas.gateway`, and nothing else from Veritas, so keep
it free of I/O-heavy or optional dependencies (tests/unit/test_architecture.py checks).
"""
