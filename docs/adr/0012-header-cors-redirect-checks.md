# 0012. Judge response headers from recon's own fetches, and probe CORS and redirects with `.invalid` origins

- Status: Accepted
- Date: 2026-11-20

## Context

Analyze can now point at missing security headers, permissive CORS, and redirect targets taken from input, in code and in recordings. Each of those candidates needs a live check that can settle it. Missing headers are among the most common real findings, but judging them must not mean crawling the site again. CORS and open-redirect checks are often written to send traffic to a server the tester controls, which this project never does (§9.4).

## Decision

- **Headers are judged on what recon already captured.** Recon now records each fetch's route, status, and content type next to its evidence ID. The CSP and framing checks plan one passive probe per HTML page, and each recorded response is one attempt. The nosniff, server-banner, and HSTS checks judge the site's first successful response. HSTS is judged only on https targets. No header check sends a request.
- **Only a missing protection counts.** Any enforced CSP passes the CSP check, and any `frame-ancestors` directive or `X-Frame-Options: DENY` or `SAMEORIGIN` passes the framing check. A report-only CSP and the obsolete `ALLOW-FROM` don't count as protection. The banner check needs a version in `Server`, or any `X-Powered-By`.
- **CORS is probed with origins nobody can own.** A signed-in GET is sent twice: once with an Origin under the reserved `.invalid` TLD, then with `Origin: null`. The check passes only when the response names exactly that origin and allows credentials. `*` with credentials, which browsers refuse, doesn't count.
- **Redirects are probed with a host that can't exist.** Only parameters whose names mean a destination (`next`, `url`, `return_to`, and others) are probed. The value is an absolute URL under `.invalid`. The executor never follows redirects, so the oracle reads only the Location header.

## Consequences

- The vuln-notes lab gains an open redirect (L9), a CORS endpoint that echoes Origin (L10), and the missing headers it already had, as H1 to H6. Each gets a look-alike where one is possible: `/go2` maps keys to fixed destinations, `/api/notes` allows only its own origin, and `/search2` sends a CSP with `frame-ancestors`.
- Site-wide headers are judged on one response, the front door. A header that only some routes miss isn't reported by those checks, though the per-page CSP and framing checks still see each page.
- These checks don't prove impact: no script runs in a frame, no page reads a cross-origin response, and no browser follows the redirect. The report says what the evidence shows, and the CVSS vector says what it would allow.
