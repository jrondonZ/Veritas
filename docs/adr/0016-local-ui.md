# 0016. A read-only local UI on loopback: stdlib server, bundled assets, data rendered as text

- Status: Accepted
- Date: 2026-11-21

## Context

The CLI writes everything a person needs to see: runs, findings with typed claims, specs, code findings, clean-room results, and patch drafts. Reading those as JSON and Markdown is slow. A UI helps, but it must stay true to the rest of the design:
- local only, with nothing fetched;
- approvals made by a person at a terminal;
- findings quote the target, so their text is hostile.

The laptop budget rules out a front-end toolchain.

## Decision

- **A stdlib HTTP server and plain files.** `veritas ui` serves one HTML page, one script, and one stylesheet from the package. There's no framework, no build step, no CDN, and no web font. The theme is a classic collegiate one, with a deep blue masthead, white paper, serif headings, and system fonts. It uses no institution's name, typeface, or marks.
- **Read-only.** The server answers GET (and HEAD) only. It opens the workspace database read-only, and it serves run files by name from an allowlist. It can't run, acknowledge, approve, or apply anything. Where an action is next, the page shows the exact command, with a copy button.
- **Loopback, a token, and the right Host.** It binds 127.0.0.1. The URL it prints carries a random token, which becomes an HttpOnly, SameSite=Strict cookie and leaves the address bar. Requests whose Host isn't this server are refused, which stops DNS rebinding. Request logging is off, because a URL can carry the token.
- **Text, never markup.** The script builds the page with DOM calls and sets every value as text. A test fails if it ever uses `innerHTML`, `document.write`, or `eval`. Every response carries a CSP with no inline script or style, `frame-ancestors 'none'`, nosniff, and no-referrer. Veritas's own header checks pass on it, and a test runs them.
- **Every view verifies.** Each run's audit chain is checked when it's shown, so the page says whether a run's record is intact.

## Consequences

- People can read a run, a spec, a clean-room result, or a patch draft in a browser, and nothing in the browser can act on the workspace.
- The UI shows only what the CLI wrote, so it adds no new source of truth. The JSON documents stay the contract.
- It's deliberately minimal: there's no search or filtering yet, and it covers one workspace at a time.
