# Vendored code

Nothing here is fetched at build or run time. Each file was downloaded once, checked against the registry's integrity hash, and committed. `tests/unit/analyze/test_js_engine.py` fails if a vendored file changes.

| File | Package | License | Registry integrity (tarball) | SHA-256 of the file |
|---|---|---|---|---|
| `acorn.mjs` | acorn 8.19.0, `dist/acorn.mjs` | MIT (`acorn.LICENSE`) | `sha512-oJlA3XiRm7Cyk6qFD2Jn8ak9B7jSy0qy00ADO3+8dpT0LSjFihQYv4C02LFCSYJV3Q37xYwwRy5m+IpIiUzqWw==` | `76254fc76529713b4dfd2532972d17a991ffd9aafeebb1f977445b5506b9fb0b` |

To update it, `npm pack acorn@<version>` into an empty directory, compare the tarball's sha512 with `npm view acorn@<version> dist.integrity`, copy `package/dist/acorn.mjs` and `package/LICENSE`, and update this table and the test.
