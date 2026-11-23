# 0010. Find weaknesses in code as candidates that Assess confirms, and read Electron archives member by member

- Status: Accepted
- Date: 2026-11-20

## Context

Veritas joins the pentest and reverse engineering, so Analyze has to find weaknesses as well as describe behavior. No tool finds every vulnerability. A static rule that is often wrong teaches people to ignore its output, and some classes, like authorization, can only be judged on a running system. Desktop apps often ship as Electron `.asar` archives. These can be hundreds of megabytes, mostly bundled dependencies, and the reference laptop has little free memory.

## Decision

- **Rules read facts and produce candidates.** The JavaScript engine records security facts: tainted strings that look like HTML or SQL, sinks (code execution, shell commands, file paths, redirects, DOM writes, `shell.openExternal`), cookie attributes, weak hashes, disabled TLS checks, Electron `webPreferences`, and string literals in known secret formats. Kernel rules (`analyze/security.py`) turn these facts into findings with status `candidate`, never `confirmed`. Each one has a CWE, its severity if confirmed, a fix, and typed claims that cite the engine record. Secret values are withheld, and only a hash prefix is shown.
- **Precision comes first.** Rules fire on explicit risky values only. A sink fires only on a value computed at run time, and the path and redirect rules also need request or IPC input. Each lab's ground truth lists correct look-alikes that must stay quiet.
- **Code points, Assess proves.** A rule with a live counterpart names it in `confirms_with`, for example `sql-from-input` → `veritas.check.sql-string-built`. Classes that static rules don't judge are listed in every report as not covered: authorization, CSRF, mass assignment, and business logic.
- **Archives are read in place.** The engine reads the asar index, then one member at a time, so memory stays near the size of the largest member. It refuses and counts names that could step out of a directory, offsets outside the file, and trees deeper than 64 levels. The app's own JavaScript is analyzed. Its pages are checked for a CSP and for `<webview>` attributes. Bundled dependencies are inventoried by name and version, not analyzed. Every file left out (unpacked, too large, or past the limits) is stated as a limitation.
- **The kernel checks the engine's account.** Each analyzed member's offset, size, and SHA-256 are recorded. The spec gate and the clean-room similarity audit slice member text from the staged copy and verify each hash, so they compare against the bytes the engine actually read.
- **The inventory is only an inventory.** Dependencies go to `sbom.cdx.json` (CycloneDX 1.5) so they can be matched against an advisory database the operator keeps locally. Veritas fetches nothing and makes no claim that a version is vulnerable.

## Consequences

- On `labs/vuln-notes` the rules find exactly the four planted code weaknesses, with precision and recall of 1.000. Each one names the Assess check that confirms the same planted item live.
- On `labs/notes-desktop`, a packed Electron app, they find all ten planted weaknesses and none of the seven look-alikes. The unpacked file is reported as not analyzed.
- Taint is tracked within a function only. Input that passes through another function, or a value built from a constant in a way the engine doesn't follow, can be missed. The ground truth measures this, and the report never claims full coverage.
- Weaknesses inside bundled dependency code aren't reported. Known-vulnerable dependencies need an advisory source, which is left to the operator for now.
