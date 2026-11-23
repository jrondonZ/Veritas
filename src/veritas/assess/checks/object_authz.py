"""Missing object-level authorization (lab L1): can one identity read another identity's object?"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from ...core.impact import Impact
from ..evidence import Exchange
from ..probes import Probe, Step
from ..recon import ReconResult, Route
from .base import Check, CheckInfo, OracleResult, PlanContext, seen


def _id_source(recon: ReconResult, route: Route, collection: str, listed: dict[str, list[str]]) -> str | None:
    """The listing whose ids a probe of `route` uses, or None when no listing fits.

    The route's own collection comes first. Otherwise a listing of the same resource qualifies: the
    same final path segment and the same item fields as the route returns, as /api/notes is for
    /api/v2/notes/{id}. That guess is safe because the probe first reads the object as its owner
    through `route`: an id that does not address the route's objects ends ambiguous, never confirmed.
    """
    if listed.get(collection):
        return collection
    name = collection.rpartition("/")[2]
    for candidate in sorted(listed):
        listing = recon.route("GET", candidate)
        if (
            listed[candidate]
            and listing is not None
            and candidate.rpartition("/")[2] == name
            and route.response_fields
            and listing.response_fields == route.response_fields
        ):
            return candidate
    return None


class ObjectAuthorization(Check):
    info = CheckInfo(
        id="veritas.check.object-authz",
        title="Missing object-level authorization",
        cwe=("CWE-639",),
        wstg=("WSTG-ATHZ-04",),
        impact=Impact.PROBE,
        cvss="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        remediation="Check ownership on every object access: scope the lookup by the signed-in user and "
        "answer 404 for objects the user does not own.",
    )

    def plan(self, recon: ReconResult, ctx: PlanContext) -> list[Probe]:
        owners = ctx.canary_owners
        if len(owners) < 2:
            return []
        reader, owner = owners[0], owners[1]
        listed = recon.objects.get(owner.id, {})
        probes = []
        for route in recon.routes:
            if route.method != "GET" or len(route.path_params) != 1 or not route.auth:
                continue
            param = route.path_params[0]
            collection, _, last = route.template.rpartition("/")
            if last != "{" + param + "}":
                continue
            source = _id_source(recon, route, collection, listed)
            if source is None:
                continue
            object_id = listed[source][0]
            path = f"{collection}/{object_id}"
            steps = (Step("owner", "GET", path, identity=owner.id), Step("reader", "GET", path, identity=reader.id))
            params: dict[str, Any] = {
                "owner": owner.id,
                "reader": reader.id,
                "owner_canary": owner.canary,
                "path": path,
            }
            listed_by = ""
            if source != collection:
                params["id_source"] = source
                listed_by = f" (listed by GET {source})"
            description = f"read {owner.id}'s object {object_id}{listed_by} as {reader.id}"
            probes.append(
                self.make_probe(("GET", route.template, param, "object"), route.label, description, steps, **params)
            )
        return probes

    def evaluate(self, probe: Probe, exchanges: Sequence[Exchange], attempt: int) -> OracleResult:
        mine, theirs = exchanges
        p = probe.params
        canary = p["owner_canary"]
        if not (mine.ok and canary in mine.text):
            hint = f"; the id came from GET {p['id_source']}" if "id_source" in p else ""
            return OracleResult.ambiguous(f"{p['owner']}'s own request did not return {p['owner']}'s canary{hint}")
        if theirs.ok and canary in theirs.text:
            return OracleResult.passed(
                f"{p['reader']} received {p['owner']}'s data",
                seen(
                    f"As {p['reader']}, GET {p['path']} (owned by {p['owner']}) returned {theirs.status} "
                    f"with {p['owner']}'s canary.",
                    theirs,
                ),
                seen(f"As {p['owner']}, the same request returned {mine.status} with {p['owner']}'s canary.", mine),
                inferred=(f"Any signed-in user can likely read any object on {probe.route} by its id.",),
            )
        return OracleResult.failed(f"as {p['reader']} the request returned {theirs.status} without {p['owner']}'s data")

    def unknowns(self, probe: Probe, ctx: PlanContext) -> list[str]:
        return ["Write and delete access to other users' objects was not tested."]
