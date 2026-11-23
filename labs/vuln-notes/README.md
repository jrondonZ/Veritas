# vuln-notes lab

**This application is intentionally vulnerable.** It exists so Veritas can be demonstrated and regression-tested against known flaws. Never deploy it, expose it on a host interface, or connect it to a network you don't control.

## Authorization

The Veritas project owns this application. It may be assessed by Veritas, in a disposable environment, on the internal Docker network that `compose.yaml` defines. `veritas.scope.yaml` references this file, so its contents are hashed into the scope digest.

## Isolation

- The lab network `vrt-lab-vuln-notes` is `internal`: it has no route to the host network or the internet, and no ports are published.
- The container runs as a non-root user with a read-only root filesystem, no capabilities, and `no-new-privileges`.
- The synthetic identities (`alice@lab.test`, `bob@lab.test`) get random passwords from `veritas lab up`. They're stored in `.veritas/labs/vuln-notes/secrets.env`, which is ignored by git.
- The app logs each SQL statement it runs, with its bound parameters but never its results, to `/logs/queries.jsonl` on the `query-log` volume. The scope declares the Veritas query-log sensor, which mounts that volume read-only with no network access. Health-check queries aren't logged, and a reset empties the log.

## Lifecycle

```text
veritas lab up vuln-notes      build, start, seed, and take snapshot s-01
veritas lab reset vuln-notes   restore snapshot s-01
veritas lab down vuln-notes    remove containers, network, and volume
```

## Contents

- `app/server.mjs` holds the routes. Each planted flaw is marked `PLANTED Lx`, and each correctly implemented look-alike is marked `CONTROL Nx`.
- `app/openapi.mjs` is the API description served at `/openapi.json`.
- `recordings/browse.har` is a browsing session on the lab, laid out as a browser's HAR export would record it. `tools/make-recording.mjs` writes it from the lab's own responses, so it needs no running lab. Every credential in it is fake and starts with `vrt-fake-`.
- `expected-findings.yaml` is the ground truth for Assess. It lists, for each item, the check and route that must produce it and its expected status.
- `veritas.charter.yaml` lets Analyze read the app's source and the recording. `expected-code-findings.yaml` is the ground truth for what Analyze finds there, before anything is sent to the running lab.
