"""Request input reaching a file path, a shell command, or an outbound request (lab L11 to L13).

These checks need the owned app's activity log, which the network-less activity-log sensor
reads: the files the app opens, the processes it starts, and the requests it makes. Each
probe sends an inert canary in one query parameter, and the oracle reads what the app did
with it. No traversal sequence, shell metacharacter, or reachable address is ever sent
(docs/architecture.md §9.4 rule 6):

- path: the canary is two marker segments joined by a slash. If a path the app opened kept
  the slash, input can add directory levels, so `../` would climb out of the folder.
- command: a canary inside a shell command line means a shell parses the input. Passed as a
  separate argument with no shell, it's inert.
- request: the canary is a URL under the reserved `.invalid` TLD, which can't resolve. If the
  app tried to reach that host, input decides where the app's requests go.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, ClassVar
from urllib.parse import urlencode, urlsplit

from ...core.impact import Impact
from ..evidence import Exchange, SensorRecord
from ..probes import Probe, Step
from ..recon import ReconResult
from .base import CheckInfo, OracleResult, PlanContext, SensorCheck, seen

Judgment = tuple[str, str, str] | None  # (verdict, reason, what the log shows), or None if nothing used the canary


class _ActivityCheck(SensorCheck):
    sensor = "activity-log"
    sink: ClassVar[str]
    looks_at: ClassVar[str]  # what the probe description says the log is searched for
    likely: ClassVar[str]  # what a pass makes likely, for the inferred claim

    def plan(self, recon: ReconResult, ctx: PlanContext) -> list[Probe]:
        if self.sensor not in ctx.sensors:
            return []
        probes = []
        for route in recon.routes:
            if route.method != "GET" or route.path_params or not route.query_params:
                continue
            identity = ctx.identities[0].id if route.auth and ctx.identities else None
            if route.auth and identity is None:
                continue
            for param in route.query_params:
                canary = ctx.marker(self.sink, route.template, param)
                probes.append(
                    self.make_probe(
                        ("GET", route.template, param, self.sink),
                        route.label,
                        f"send a canary in {param!r} and look for it in {self.looks_at}",
                        self._steps(route.template, param, canary, identity, 1),
                        canary=canary,
                        param=param,
                        path=route.template,
                        identity=identity,
                    )
                )
        return probes

    def value(self, canary: str) -> str:
        return canary

    def _steps(self, path: str, param: str, canary: str, identity: str | None, attempt: int) -> tuple[Step, ...]:
        query = urlencode({param: self.value(f"{canary}-{attempt}")})
        return (Step("canary", "GET", f"{path}?{query}", identity=identity),)

    def steps_for(self, probe: Probe, attempt: int) -> tuple[Step, ...]:
        p = probe.params
        return self._steps(p["path"], p["param"], p["canary"], p["identity"], attempt)

    def markers(self, probe: Probe, attempt: int) -> tuple[str, ...]:
        return (f"{probe.params['canary']}-{attempt}",)

    def judge(self, canary: str, entries: list[dict[str, Any]]) -> Judgment:
        raise NotImplementedError

    def evaluate_signals(
        self, probe: Probe, exchanges: Sequence[Exchange], signals: Sequence[SensorRecord], attempt: int
    ) -> OracleResult:
        (sent,) = exchanges
        (record,) = signals
        (canary,) = self.markers(probe, attempt)
        param = probe.params["param"]
        request = seen(
            f"GET {probe.params['path']} sent the canary {canary} in {param!r}; it returned {sent.status}.", sent
        )
        entries = list(record.entries)
        judged = self.judge(canary, entries)
        if judged is not None:
            verdict, reason, shows = judged
            if verdict == "pass":
                inferred = (f"{param!r} {self.likely}; it was not attempted.",)
                return OracleResult.passed(reason, request, seen(shows, record), inferred=inferred)
            return OracleResult.failed(reason, request, seen(shows, record))
        if entries:  # the canary went somewhere else: a file path, a command, or a request this check doesn't judge
            kinds = ", ".join(sorted({str(e.get("kind")) for e in entries}))
            return OracleResult.failed(
                f"the app used the canary only in other activity ({kinds})",
                request,
                seen(f"The app's activity log shows the canary only in {kinds} entries.", record),
            )
        if record.truncated or record.malformed:
            return OracleResult.ambiguous("the activity log could not be read completely", request)
        if sent.status >= 400:
            return OracleResult.ambiguous(
                f"the request returned {sent.status} and the app logged no use of it", request
            )
        return OracleResult.failed(f"the app logged no use of the parameter in {self.looks_at}", request)

    def limitations(self, probe: Probe, ctx: PlanContext) -> list[str]:
        return ["Only what the app writes to its activity log is visible to the sensor."]


class PathFromInput(_ActivityCheck):
    sink = "path"
    looks_at = "the file paths the app opens"
    likely = "can add directory levels to a file path, so path traversal is likely"
    info = CheckInfo(
        id="veritas.check.path-from-input",
        title="File path built from request input",
        cwe=("CWE-22",),
        wstg=("WSTG-ATHZ-01",),
        impact=Impact.PROBE,
        cvss="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        remediation="Resolve paths against a fixed base directory and refuse anything outside it, or map IDs to "
        "files. Never pass request input to the file system as a path.",
    )

    def value(self, canary: str) -> str:
        return f"{canary}/{canary}"

    def judge(self, canary: str, entries: list[dict[str, Any]]) -> Judgment:
        paths = [str(e.get("path", "")) for e in entries if e.get("kind") == "file"]
        if any(f"{canary}/{canary}" in p for p in paths):
            return (
                "pass",
                "a file path the app opened kept the canary's slash",
                ("The app's activity log shows it opening a path that contains the canary with its slash intact."),
            )
        if any(canary in p for p in paths):
            return (
                "fail",
                "the canary reached a file path only as a file name",
                ("The app's activity log shows the canary in a file path, without the slash it was sent with."),
            )
        return None


class CommandFromInput(_ActivityCheck):
    sink = "command"
    looks_at = "the commands the app runs"
    likely = "is parsed by a shell, so command injection is likely"
    info = CheckInfo(
        id="veritas.check.command-from-input",
        title="Shell command built from request input",
        cwe=("CWE-78",),
        wstg=("WSTG-INPV-12",),
        impact=Impact.PROBE,
        cvss="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        remediation="Run programs with an argument array and no shell (execFile or spawn), and allowlist the values.",
    )

    def judge(self, canary: str, entries: list[dict[str, Any]]) -> Judgment:
        execs = [e for e in entries if e.get("kind") == "exec"]
        if any(e.get("shell") is True and canary in str(e.get("command", "")) for e in execs):
            return (
                "pass",
                "the canary appeared inside a shell command line",
                ("The app's activity log shows the canary inside a command line it ran through a shell."),
            )
        if any(e.get("shell") is False and canary in str(e.get("file", "")) for e in execs):
            return (
                "pass",
                "the canary chose which program the app ran",
                ("The app's activity log shows the canary as the program it started."),
            )
        if any(e.get("shell") is False and any(canary in str(a) for a in e.get("args") or []) for e in execs):
            return (
                "fail",
                "the canary was passed as a separate argument, with no shell",
                ("The app's activity log shows the canary only as one argument of a program started without a shell."),
            )
        return None


class RequestFromInput(_ActivityCheck):
    sink = "request"
    looks_at = "the requests the app makes"
    likely = "decides where the app sends requests, so server-side request forgery is likely"
    info = CheckInfo(
        id="veritas.check.request-from-input",
        title="Outbound request controlled by request input",
        cwe=("CWE-918",),
        wstg=("WSTG-INPV-19",),
        impact=Impact.PROBE,
        cvss="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N",
        remediation="Request only hosts on an allowlist, or map a key to fixed URLs. Check the resolved address before "
        "connecting, and refuse private and loopback ranges.",
    )

    def value(self, canary: str) -> str:
        return f"http://{canary}.invalid/"

    def judge(self, canary: str, entries: list[dict[str, Any]]) -> Judgment:
        urls = [str(e.get("url", "")) for e in entries if e.get("kind") == "request"]

        def host(url: str) -> str:
            try:
                return (urlsplit(url).hostname or "").rstrip(".").lower()
            except ValueError:
                return ""

        if any(host(u) == f"{canary}.invalid".lower() for u in urls):
            return (
                "pass",
                "the app tried to reach the canary's host",
                ("The app's activity log shows an outbound request to the host the canary named, which can't exist."),
            )
        if any(canary in u for u in urls):
            return (
                "fail",
                "the canary reached an outbound request but didn't choose its host",
                ("The app's activity log shows the canary inside an outbound request to a fixed host."),
            )
        return None
