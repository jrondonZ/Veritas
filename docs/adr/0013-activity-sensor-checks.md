# 0013. Decide path, command, and outbound-request flaws from the app's own activity log

- Status: Accepted
- Date: 2026-11-20

## Context

Path traversal, command injection, and server-side request forgery are high-impact flaws. Testing for them from outside usually means sending `../`, shell metacharacters, or an address the app shouldn't reach. That's exploitation, which this project never does (§9.4). On an owned app there's a better witness: the app itself. The query-log sensor (ADR 0006) already settles SQL built from input this way.

## Decision

- **The app logs what it's about to do.** An owned app appends one JSON line before each file it opens, process it starts, and outbound request it makes. The activity-log sensor reads that log with no network and the volume mounted read-only. It returns only the entries that mention the attempt's canary, and only the fields each kind defines.
- **The canaries are inert:**
  - **path:** two marker segments joined by a slash;
  - **command:** a plain marker;
  - **request:** a URL under the reserved `.invalid` TLD.

  The oracles read what the app did with them. A path that kept the slash means input can add directory levels. A marker inside a shell command line means a shell parses the input; as a separate argument without a shell, it's inert. A request to the marker's host means input chooses where the app's requests go.
- **Where the input went is decided, not guessed.** When the canary shows up only in another kind of activity, the check fails with that reason, and isn't left inconclusive. A redirect counts as a handled request, not an error.
- **The lab stays inert even by hand.** The vuln-notes lab gets three planted flaws (L11 to L13) and their look-alikes (N9 to N11). Its shell is `/bin/false`, so no command it builds ever runs. Its outbound requests are aborted before they're sent. Only the file read is real, and it reads inside the lab container.
- **Analyze points at the same places.** The JavaScript engine now follows `basename()` and local variables when it judges a file path. Outbound requests built from input are a new sink, `request-from-input`. The code rules name the matching live checks in `confirms_with`.

## Consequences

- Each flaw is confirmed from the app's own record of what it did, with no attack input on the wire, and each look-alike stays quiet.
- This works only for apps whose owners can add the log, the same limit as the query-log sensor. Third-party targets still need the Phase 4 approach.
- Input that's transformed before use, for example base64-decoded, carries no marker and isn't seen. The check then says the app logged no use of the parameter, not that the parameter is safe.
