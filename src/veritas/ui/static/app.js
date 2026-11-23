// Veritas central page. Read-only: it shows the workspace snapshot embedded in this file and fetches nothing.
// Nothing is ever parsed as markup. Findings quote the target, so every value is set as text.
"use strict";

const DATA = JSON.parse(document.getElementById("veritas-data").textContent);
const main = document.getElementById("main");

function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (value === null || value === undefined || value === false) continue;
    if (key === "class") el.className = value;
    else if (key.startsWith("on")) el.addEventListener(key.slice(2), value);
    else el.setAttribute(key, value === true ? "" : String(value));
  }
  for (const child of children.flat(Infinity)) {
    if (child === null || child === undefined || child === false) continue;
    el.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return el;
}

const when = (iso) => (iso ? new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }) : "—");
const plural = (n, word) => `${n} ${word}${n === 1 ? "" : "s"}`;
const lower = (...parts) => parts.flat().filter(Boolean).join(" ").toLowerCase();

function badge(text, tone) {
  return h("span", { class: `badge ${tone || "plain"}` }, text);
}

const STATUS_TONE = { confirmed: "solid", rejected: "plain", inconclusive: "warn", blocked: "plain", error: "bad" };
const OUTCOME_TONE = { completed: "good", completed_with_gaps: "warn", failed: "bad", aborted: "bad" };
const status = (text) => badge(text || "—", STATUS_TONE[text] || "plain");
const outcome = (text) => badge((text || "running").replaceAll("_", " "), OUTCOME_TONE[text] || "plain");
const severity = (level) => (level ? h("span", { class: `sev sev-${level}` }, level) : h("span", { class: "quiet" }, "—"));

function command(text) {
  const code = h("code", {}, text);
  const button = h("button", { class: "copy", type: "button" }, "Copy");
  button.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(text);
      button.textContent = "Copied";
    } catch {
      const range = document.createRange();  // no clipboard on this page: select the command instead
      range.selectNodeContents(code);
      const selection = window.getSelection();
      selection.removeAllRanges();
      selection.addRange(range);
      button.textContent = "Selected";
    }
    setTimeout(() => { button.textContent = "Copy"; }, 1600);
  });
  return h("div", { class: "command" }, code, button);
}

function table(columns, rows, numeric = []) {
  return h("div", { class: "table" }, h("table", {},
    h("thead", {}, h("tr", {}, columns.map((c, i) => h("th", { class: numeric.includes(i) ? "num" : null, scope: "col" }, c)))),
    h("tbody", {}, rows)));
}

// A search box and choice lists over table rows. Each item is {rows: [tr...], text, fields}.
function filtered(items, choices, render) {
  const query = h("input", { type: "search", placeholder: "Search", "aria-label": "Search", class: "search" });
  const selects = choices.map(([field, label, options]) => h("select", { "aria-label": label },
    h("option", { value: "" }, label), options.map((o) => h("option", { value: o }, o))));
  const count = h("span", { class: "quiet count" });
  const apply = () => {
    const words = query.value.toLowerCase().split(/\s+/).filter(Boolean);
    let shown = 0;
    for (const item of items) {
      const ok = words.every((w) => item.text.includes(w))
        && choices.every(([field], i) => !selects[i].value || item.fields[field] === selects[i].value);
      item.rows[0].hidden = !ok;
      if (item.rows[1] && !ok) {  // a row that's filtered out closes, so it comes back collapsed
        item.rows[1].hidden = true;
        item.rows[0].classList.remove("open");
        item.rows[0].setAttribute("aria-expanded", "false");
      }
      if (ok) shown += 1;
    }
    count.textContent = shown === items.length ? plural(items.length, "row") : `${shown} of ${items.length}`;
  };
  query.addEventListener("input", apply);
  selects.forEach((s) => s.addEventListener("change", apply));
  const body = render(items.flatMap((i) => i.rows));
  apply();
  return h("div", {}, h("div", { class: "toolbar" }, query, selects, count), body);
}

function expandable(cells, detail) {
  const row = h("tr", { class: "row", tabindex: "0", "aria-expanded": "false" }, cells);
  const extra = h("tr", { class: "detail", hidden: true }, h("td", { colspan: String(cells.length) }, detail));
  const toggle = () => {
    extra.hidden = !extra.hidden;
    row.classList.toggle("open", !extra.hidden);
    row.setAttribute("aria-expanded", extra.hidden ? "false" : "true");
  };
  row.addEventListener("click", toggle);
  row.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggle(); } });
  return [row, extra];
}

function claimsList(claims) {
  return h("ul", { class: "claims" }, (claims || []).map((c) => h("li", {},
    h("span", { class: `kind ${c.kind}` }, c.kind), h("span", {}, c.text),
    (c.evidence || []).length ? h("span", { class: "mono quiet cite" }, c.evidence.join(" ")) : null)));
}

function section(id, title, ...children) {
  return h("section", { id, class: "section" }, h("h2", {}, title), children);
}

// ------------------------------------------------------------------ the workspace

function results(run) {
  const c = run.counts || {};
  if (run.kind === "Assess") {
    return ["confirmed", "rejected", "inconclusive", "blocked", "error"].filter((k) => c[k]).map((k) => `${c[k]} ${k}`)
      .join(" · ") || "no findings";
  }
  if (run.kind === "Analyze") {
    return [plural(c.candidates || 0, "candidate"), plural(c.claims || 0, "claim"),
      run.approved ? "spec approved" : null, run.verifications ? plural(run.verifications, "verification") : null]
      .filter(Boolean).join(" · ");
  }
  return c.results ? plural(c.results, "result") : "";
}

function stage(name, purpose, runs, figure, figureLabel, tally) {
  return h("section", { class: "panel" },
    h("div", { class: "eyebrow" }, name),
    h("h3", {}, purpose),
    h("div", { class: "figure" }, String(figure), h("small", {}, figureLabel)),
    h("div", { class: "quiet" }, tally || plural(runs.length, "run"),
      runs[0] ? [" · latest ", h("a", { href: `#/run/${runs[0].id}` }, runs[0].id)] : null));
}

function overviewView() {
  const o = DATA.overview;
  const of = (kind) => o.runs.filter((r) => r.kind === kind);
  const assess = of("Assess");
  const analyze = of("Analyze");
  const confirmed = assess.reduce((n, r) => n + ((r.counts || {}).confirmed || 0), 0);
  const candidates = analyze.reduce((n, r) => n + ((r.counts || {}).candidates || 0), 0);
  const approved = analyze.filter((r) => r.approved);
  const items = o.runs.map((run) => {
    const open = () => { location.hash = `#/run/${run.id}`; };
    const row = h("tr", { class: "row", tabindex: "0", onclick: open, onkeydown: (e) => { if (e.key === "Enter") open(); } },
      h("td", { class: "mono" }, run.id), h("td", {}, run.kind), h("td", {}, run.subject || "—"),
      h("td", {}, outcome(run.outcome)), h("td", {}, when(run.created)), h("td", {}, results(run)));
    return { rows: [row], text: lower(run.id, run.kind, run.subject, run.outcome, results(run)),
      fields: { kind: run.kind, outcome: (run.outcome || "running").replaceAll("_", " ") } };
  });
  const kinds = [...new Set(o.runs.map((r) => r.kind))];
  const outcomes = [...new Set(items.map((i) => i.fields.outcome))];
  return h("div", {},
    h("div", { class: "eyebrow" }, `Veritas ${o.veritas} · ${o.profile} profile`),
    h("h1", {}, "Workspace"),
    h("p", { class: "lead" }, "Validate the security of software you own, reverse-engineer how it behaves with evidence "
      + "for every claim, and replicate that behavior clean-room. Every run is recorded in a hash-linked audit chain."),
    h("div", { class: "grid three" },
      stage("Assess", "Validate controls on a running target", assess, confirmed, "confirmed findings"),
      stage("Analyze", "Read code, archives, binaries, and recordings", analyze, candidates, "candidates in code"),
      stage("Replicate", "Clean-room work from an approved spec", approved, approved.length, "approved specs",
        plural(analyze.reduce((n, r) => n + (r.verifications || 0), 0), "clean-room verification"))),
    section("runs", "Runs", o.runs.length
      ? filtered(items, [["kind", "All kinds", kinds], ["outcome", "All outcomes", outcomes]],
        (rows) => table(["Run", "Kind", "Subject", "Outcome", "Started", "Results"], rows))
      : h("p", { class: "quiet" }, "No runs yet. Start with a lab, using the commands below.")),
    h("div", { class: "grid two" }, section("models", "Local models", modelsPanel(o)), section("labs", "Labs", labsPanel(o))),
    section("terminal", "At the terminal",
      h("p", { class: "lead" }, "This page only reads. These commands run, acknowledge, approve, and replicate, and each "
        + "one asks before it acts. Every command that changes the workspace rewrites this page."),
      ["veritas lab up vuln-notes", "veritas scope check labs/vuln-notes/veritas.scope.yaml",
        "veritas assess run --scope labs/vuln-notes/veritas.scope.yaml",
        "veritas charter check labs/lexfmt/veritas.charter.yaml", "veritas analyze run --charter labs/lexfmt/veritas.charter.yaml",
        "veritas advisories import path/to/osv-export.zip", "veritas models eval", "veritas ui"].map(command)));
}

function modelsPanel(o) {
  const registered = o.models.length
    ? table(["Model", "Quantization", "License", "Size"], o.models.map((m) => h("tr", {}, h("td", { class: "mono" }, m.name),
      h("td", {}, m.quantization), h("td", {}, m.license), h("td", { class: "num" }, `${m.gib} GiB`))), [3])
    : h("p", { class: "quiet" }, "No weights registered. Models are optional, and Veritas never downloads any.");
  const routes = table(["Route", "Served by"], o.routes.map((r) => h("tr", {}, h("td", {}, r.route),
    h("td", {}, r.model ? [h("span", { class: "mono" }, r.model), r.aliased_to ? h("span", { class: "quiet" }, ` via ${r.aliased_to}`) : null]
      : h("span", { class: "quiet" }, "not set")))));
  const advisories = o.advisories && o.advisories.records
    ? h("p", { class: "quiet" }, `${plural(o.advisories.records, "advisory")} imported for offline dependency checks, `
      + `from ${plural(o.advisories.sources.length, "source")}.`)
    : h("p", { class: "quiet" }, "No advisories imported, so bundled dependencies are inventoried but not checked.");
  return h("div", {}, registered, h("h3", {}, "Routes"), routes, h("h3", {}, "Advisories"), advisories);
}

function labsPanel(o) {
  if (!o.labs.length) return h("p", { class: "quiet" }, "No labs in this project.");
  return table(["Lab", "Assess", "Analyze"], o.labs.map((lab) => h("tr", {},
    h("td", { class: "mono" }, lab.name),
    h("td", {}, lab.scope ? badge("scope", "plain") : h("span", { class: "quiet" }, "—")),
    h("td", {}, lab.charter ? badge("charter", "plain") : h("span", { class: "quiet" }, "—")))));
}

// ------------------------------------------------------------------ one run

function runView(id) {
  const run = DATA.runs[id];
  if (!run) {
    return h("div", {}, h("div", { class: "eyebrow" }, h("a", { href: "#/" }, "Workspace")), h("h1", {}, id),
      h("div", { class: "notice" }, `This page keeps the newest ${DATA.kept} runs in full. The terminal prints this one:`,
        command(`veritas show ${id}`)));
  }
  const head = h("div", {},
    h("div", { class: "eyebrow" }, h("a", { href: "#/" }, "Workspace"), ` · ${run.kind}`),
    h("h1", {}, `${run.id} · ${subjectOf(run)}`),
    h("div", { class: "meta" }, outcome(run.outcome),
      run.audit.ok ? badge(`audit chain verified · ${run.audit.entries} entries`, "good")
        : badge(`audit problem: ${run.audit.problems.join("; ")}`, "bad"),
      h("span", {}, "Started ", h("b", {}, when(run.created)))),
    run.files.length ? h("div", { class: "meta files" }, "Files:", run.files.filter((f) => !f.startsWith("patches/"))
      .map((f) => h("a", { href: `runs/${run.id}/${f}` }, f))) : null);
  let body;
  if (run.kind === "Assess") body = assessBody(run);
  else if (run.kind === "Analyze") body = analyzeBody(run);
  else if (run.eval) body = evalBody(run.eval);
  else body = h("p", { class: "quiet" }, "This run recorded no document the page knows how to show.");
  return h("div", {}, head, body);
}

function subjectOf(run) {
  if (run.assessment) return (run.assessment.scope || {}).name || "assessment";
  if (run.analysis) return (run.analysis.charter || {}).name || "analysis";
  return run.kind;
}

function assessBody(run) {
  const doc = run.assessment || {};
  const summary = doc.summary || {};
  const findings = doc.findings || [];
  const items = findings.map((f) => ({
    rows: expandable([
      h("td", { class: "mono" }, f.id), h("td", {}, status(f.status)), h("td", {}, severity(f.severity)),
      h("td", {}, f.title), h("td", { class: "mono" }, (f.cwe || []).join(" ")),
      h("td", { class: "num" }, `${f.passed ?? 0}/${f.attempts ?? 0}`),
    ], h("div", {},
      f.reason ? h("p", { class: "quiet" }, f.reason) : null,
      claimsList(f.claims),
      f.cvss ? h("p", {}, "CVSS ", h("span", { class: "mono" }, `${f.cvss.vector} · ${f.cvss.score}`)) : null,
      (f.repro || []).length ? [h("h3", {}, "To reproduce"), h("ul", { class: "plain mono" }, f.repro.map((r) => h("li", {}, r)))] : null,
      command(`veritas reproduce ${run.id} ${f.id}`))),
    text: lower(f.id, f.title, f.route, f.check, f.cwe, f.status, f.severity),
    fields: { status: f.status || "", severity: f.severity || "" },
  }));
  const recon = doc.recon || {};
  return h("div", {},
    h("div", { class: "meta" }, doc.target ? ["Target ", h("b", { class: "mono" }, doc.target.base_url)] : null,
      doc.duration_s !== undefined ? h("span", {}, `${doc.duration_s} s`) : null,
      h("span", {}, `models ${(doc.models || {}).status || "off"}`)),
    h("div", { class: "chips" }, ["confirmed", "rejected", "inconclusive", "blocked", "error"].map((k) =>
      h("span", { class: "chip" }, h("b", {}, String(summary[k] || 0)), k))),
    section("findings", "Findings", findings.length
      ? filtered(items, [["status", "All statuses", ["confirmed", "rejected", "inconclusive", "blocked", "error"]],
        ["severity", "All severities", ["critical", "high", "medium", "low"]]],
        (rows) => table(["ID", "Status", "Severity", "Finding", "CWE", "Passed"], rows, [5]))
      : h("p", { class: "quiet" }, "No findings.")),
    section("recon", "Recon",
      h("p", {}, `${plural((recon.routes || []).length, "route")} · ${plural(recon.fetches || 0, "fetch")} · `
        + `${plural((recon.external_links || []).length, "external link")} recorded, never fetched`),
      (recon.skipped || []).length ? h("ul", { class: "plain quiet" }, recon.skipped.map((s) => h("li", {}, s))) : null));
}

function tabs(sections) {
  const bar = h("div", { class: "tabs", role: "tablist" });
  const panel = h("div", { role: "tabpanel" });
  const buttons = sections.map(([label, render], i) => {
    const button = h("button", { type: "button", role: "tab", "aria-selected": i === 0 ? "true" : "false" }, label);
    button.addEventListener("click", () => {
      buttons.forEach((b) => b.setAttribute("aria-selected", b === button ? "true" : "false"));
      panel.replaceChildren(render());
    });
    return button;
  });
  bar.append(...buttons);
  panel.append(sections[0][1]());
  return h("div", {}, bar, panel);
}

function analyzeBody(run) {
  const doc = run.analysis || {};
  const spec = run.spec || {};
  const approval = run.approved
    ? h("div", { class: "notice" }, "This spec version is approved. A clean room may use it.",
      command(`veritas cleanroom verify ${run.id} --impl path/to/implementation`))
    : h("div", { class: "notice" }, "The spec isn't approved. Nothing crosses into a clean room until a person approves "
      + "its digest at the terminal.", command(`veritas spec approve ${run.id}`));
  return h("div", {},
    h("div", { class: "meta" }, h("span", {}, "Basis ", h("b", {}, (doc.charter || {}).basis || "—")),
      spec.digest ? h("span", {}, "Spec ", h("span", { class: "mono" }, spec.digest)) : null),
    approval,
    tabs([
      [`Security findings (${run.code.length})`, () => codeFindings(run)],
      ["Behavior spec", () => specView(spec)],
      ["Subjects", () => subjectsView(doc)],
      [`Clean room (${run.cleanroom.length})`, () => cleanroomView(run)],
      [`Patch drafts (${run.patches.length})`, () => patchesView(run)],
    ]));
}

function codeFindings(run) {
  if (!run.code.length) return h("p", { class: "quiet" }, "No candidates from the static rules.");
  const doc = run.analysis || {};
  const owned = (doc.charter || {}).basis === "owned";  // patch drafts are for owned JavaScript source
  const patchable = new Set((doc.subjects || []).filter((s) => s.type === "javascript" && s.staged).map((s) => s.path));
  const items = run.code.map((f) => ({
    rows: expandable([
      h("td", { class: "mono" }, f.id), h("td", {}, severity(f.if_confirmed.severity)), h("td", {}, f.title),
      h("td", { class: "mono" }, f.line ? `${f.file}:${f.line}` : f.file, f.function ? h("div", { class: "quiet" }, f.function) : null),
      h("td", { class: "mono" }, f.confirms_with || "review"),
    ], h("div", {},
      claimsList(f.claims),
      h("p", {}, "If confirmed ", h("span", { class: "mono" }, `${f.if_confirmed.cvss.vector} · ${f.if_confirmed.cvss.score}`),
        ` · ${(f.cwe || []).join(" ")}`),
      owned && patchable.has(f.file) ? command(`veritas patch draft ${run.id} ${f.id}`) : null)),
    text: lower(f.id, f.title, f.rule, f.file, f.function, f.cwe, f.confirms_with),
    fields: { severity: f.if_confirmed.severity || "", live: f.confirms_with ? "has a live check" : "review" },
  }));
  return h("div", {},
    h("p", { class: "lead" }, "Candidates from reading the subjects, without sending any traffic. Where a live check exists, "
      + "Assess confirms or rules each one out on a running target."),
    filtered(items, [["severity", "All severities", ["critical", "high", "medium", "low"]],
      ["live", "Live check or review", ["has a live check", "review"]]],
    (rows) => table(["ID", "If confirmed", "Finding", "Where", "Confirm live with"], rows)));
}

function specView(spec) {
  if (!spec.interfaces) return h("p", { class: "quiet" }, "No spec was written.");
  return h("div", {}, spec.interfaces.map((i) => h("section", {},
    h("h3", {}, `${i.id} · ${i.title}`), claimsList(i.claims))));
}

function subjectsView(doc) {
  const rows = (doc.subjects || []).map((s) => h("tr", {},
    h("td", { class: "mono" }, s.path), h("td", {}, s.type), h("td", { class: "mono" }, `${(s.sha256 || "").slice(0, 16)}…`),
    h("td", {}, s.error ? h("span", { class: "sev-critical" }, s.error)
      : Object.entries(s.counts || {}).map(([k, v]) => `${k} ${v}`).join(", "))));
  return h("div", {}, table(["Subject", "Type", "SHA-256", "Facts"], rows),
    (doc.limitations || []).length ? [h("h3", {}, "Limitations"),
      h("ul", { class: "plain" }, doc.limitations.map((l) => h("li", {}, l)))] : null);
}

function cleanroomView(run) {
  if (!run.cleanroom.length) {
    return h("div", {}, h("p", { class: "quiet" }, "No clean-room verification yet."),
      command(`veritas cleanroom verify ${run.id} --impl path/to/implementation`), command(`veritas cleanroom draft ${run.id}`));
  }
  const rows = run.cleanroom.map((c) => {
    const conf = c.conformance || {};
    const sim = c.similarity || {};
    const passed = conf.total ? `${conf.passed}/${conf.total}` : "—";
    const similar = sim.overall !== undefined ? `${Math.round(sim.overall * 100)}% (limit ${Math.round((sim.limit || 0) * 100)}%)` : "—";
    return h("tr", {}, h("td", { class: "mono" }, c.task), h("td", { class: "num" }, passed), h("td", { class: "num" }, similar),
      h("td", {}, sim.similar ? badge("too similar", "bad") : badge("independent", "good")));
  });
  return h("div", {}, h("p", { class: "lead" }, "Similarity results are for the operator only. They never go back into a clean room."),
    table(["Task", "Vectors passed", "Similarity", "Audit"], rows, [1, 2]));
}

function patchesView(run) {
  if (!run.patches.length) return h("p", { class: "quiet" }, "No patch drafts. Draft one from a security finding's row.");
  return h("div", {}, run.patches.filter(Boolean).map((p) => {
    const v = p.verification || {};
    const checks = v.parses === undefined ? null : h("div", { class: "chips" },
      h("span", { class: "chip" }, v.parses ? "parses" : "doesn't parse"),
      h("span", { class: "chip" }, v.finding_gone ? "finding gone" : "finding still there"),
      h("span", { class: "chip" }, plural((v.new_findings || []).length, "new finding")));
    const lines = (p.diff_text || "").split("\n");
    const diff = p.diff_text ? h("pre", { class: "diff" }, lines.map((line) => h("span", { class: line.startsWith("@@") ? "hunk"
      : line.startsWith("+") ? "add" : line.startsWith("-") ? "del" : "ctx" }, line || " "))) : h("p", { class: "quiet" }, "No diff.");
    return h("section", { class: "panel" },
      h("h3", {}, `${p.finding} · `, p.verified ? badge("verified", "good") : badge(p.status, "warn")),
      p.reason ? h("p", { class: "quiet" }, p.reason) : null,
      checks, p.notes ? h("p", {}, p.notes) : null, diff,
      h("p", { class: "quiet" }, "Review it, then apply it yourself, for example with git apply. Veritas never applies a patch."));
  }));
}

function evalBody(report) {
  const rows = [];
  for (const [route, models] of Object.entries(report.scores || {})) {
    for (const [model, s] of Object.entries(models)) {
      const best = (report.recommended || {})[route] === model;
      rows.push(h("tr", {}, h("td", {}, route), h("td", { class: "mono" }, model), h("td", { class: "num" }, s.score.toFixed(2)),
        h("td", { class: "num" }, `${s.seconds} s`), h("td", {}, best ? badge("recommended", "good") : null)));
    }
  }
  return h("div", {},
    section("scores", "Scores",
      rows.length ? table(["Route", "Model", "Score", "Mean time", ""], rows, [2, 3]) : h("p", { class: "quiet" }, "No results."),
      (report.skipped || []).length ? h("ul", { class: "plain quiet" }, report.skipped.map((s) => h("li", {}, s))) : null,
      command("veritas models eval --apply")));
}

// ------------------------------------------------------------------ the frame

const motion = () => (window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth");

function subnav(onRun) {
  const nav = document.getElementById("subnav");
  const jump = (id, label) => h("button", { type: "button",
    onclick: () => document.getElementById(id)?.scrollIntoView({ behavior: motion() }) }, label);
  const print = h("button", { type: "button", onclick: () => window.print() }, "Print");
  nav.replaceChildren(...(onRun ? [h("a", { href: "#/" }, "← Workspace"), print]
    : [jump("runs", "Runs"), jump("models", "Models"), jump("labs", "Labs"), jump("terminal", "At the terminal"), print]));
}

function render() {
  const match = /^#\/run\/(r-\d{4,6})$/.exec(location.hash || "#/");
  main.replaceChildren(match ? runView(match[1]) : overviewView());
  subnav(Boolean(match));
  main.focus({ preventScroll: true });
  window.scrollTo(0, 0);
}

document.getElementById("stamp").textContent = `Snapshot · ${when(DATA.generated)}`;
document.getElementById("colophon").textContent = `Generated by Veritas ${DATA.overview.veritas} on ${when(DATA.generated)} `
  + "from this workspace. This page is a read-only snapshot. Every command that changes the workspace rewrites it, "
  + "and veritas ui opens it.";
window.addEventListener("hashchange", render);
render();
