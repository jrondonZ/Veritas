# 0011. Read HAR recordings for their shape only, and never store them raw

- Status: Accepted
- Date: 2026-11-20

## Context

A browser's HAR export shows how an app is really used, including endpoints that neither the OpenAPI document nor a crawl reveals. It also shows response headers, cookies, and error bodies that point to weaknesses. But a HAR file holds live session cookies, bearer tokens, and personal data. The brief forbids extracting credentials or private user data. Analyze normally copies every subject into the evidence store, and evidence bundles are made to be exported and shared.

## Decision

- **One reader keeps the shape and drops the values.** `veritas.imports.har` uses only the standard library and caps sizes. Headers keep their names, and `Authorization` keeps only its scheme. Cookies, query parameters, and form fields keep their names. JSON bodies keep field names and value types. Path segments and JSON keys that look like IDs, email addresses, or tokens become placeholders. Responses keep yes-or-no security facts: a CSP, framing protection, HSTS, nosniff, and a stack trace in the body. They keep values only for `Server`, `X-Powered-By`, and CORS headers.
- **A recording is never stored raw.** Analyze checks the recording against the charter's hash, reads it in memory, and stores only the catalog as evidence. No copy goes to the run's inputs or the evidence store. Assess reads a recording at run time, only after checking it against the hash in the acknowledged scope digest.
- **In Analyze, the catalog is an interface.** Each endpoint on the app's own origins becomes an observed claim under "HTTP endpoints". What a recording shows on the wire (routes, parameter and field names, media types) is public by definition, so the spec gate allows it the same way it allows exported names. Passive rules judge the app's own responses as candidates:
  - cookie attributes and Secure;
  - a missing CSP, framing protection, nosniff, or HSTS;
  - server software named in headers;
  - credentials in URLs;
  - CORS that trusts the `null` origin;
  - stack traces in responses.

  Other origins, such as CDNs and trackers, are catalogued but not judged.
- **In Assess, a recording only adds routes.** A target can list `recordings` in its scope. Recon adds the routes they show on the target's origin and in scope, but only those that the OpenAPI document and the crawl didn't find. Recordings are never replayed. Out-of-scope endpoints are listed as skipped, and other origins as external.

## Consequences

- On `labs/vuln-notes`, the source and a recorded session read together give the nine expected candidates, with precision and recall of 1.000. None lands in a look-alike, such as the cleared logout cookie or the CDN's responses. A test searches the whole workspace afterwards and finds no fake credential from the recording.
- A recording shows only what someone clicked through, so it adds coverage without proving completeness.
- The header rules have no live Assess check yet, so their candidates name none. Adding one is the next Assess step.
