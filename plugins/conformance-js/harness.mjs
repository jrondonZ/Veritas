// Veritas conformance harness (docs/architecture.md §8.3 step 8): runs a clean-room implementation against the
// operator-owned conformance vectors. It executes only the implementation, never the subject. It runs with no
// network; the implementation is mounted read-only at /impl and the samples at /samples. The job is one JSON
// object on stdin, and the result is one JSON object on stdout.
import { readFileSync } from "node:fs";
import { isAbsolute, join, normalize, sep } from "node:path";
import { pathToFileURL } from "node:url";

const IMPL = process.env.VERITAS_IMPL ?? "/impl";
const SAMPLES = process.env.VERITAS_SAMPLES ?? "/samples";

function inside(base, relative) {
  if (typeof relative !== "string" || isAbsolute(relative) || normalize(relative).split(sep).includes("..")) {
    throw new Error(`refused path ${JSON.stringify(relative)}`);
  }
  return join(base, relative);
}

// Compare as JSON values: byte arrays become plain arrays and object key order doesn't matter.
function canonical(value) {
  if (value instanceof Uint8Array) return Array.from(value);
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((k) => [k, canonical(value[k])]));
  }
  return typeof value === "bigint" ? String(value) : value;
}

function summarize(got) {
  if (!got.ok) return { ok: false, error: got.error };
  const text = JSON.stringify(got.value);
  return { ok: true, value: text.length > 400 ? `${text.slice(0, 400)}…` : JSON.parse(text) };
}

const job = JSON.parse(readFileSync(0, "utf8"));
let fn = null;
let loadError = null;
try {
  const mod = await import(pathToFileURL(inside(IMPL, job.entry)).href);
  fn = typeof mod[job.call] === "function" ? mod[job.call] : null;
  if (!fn) loadError = `the implementation does not export a function named ${job.call}`;
} catch (err) {
  loadError = `the implementation failed to load: ${String(err?.message ?? err).slice(0, 200)}`;
}
const results = [];
for (const vector of job.vectors) {
  if (!fn) {
    results.push({ id: vector.id, pass: false, got: { ok: false, error: loadError } });
    continue;
  }
  let got;
  try {
    const bytes = new Uint8Array(readFileSync(inside(SAMPLES, vector.sample)));
    got = { ok: true, value: canonical(await fn(bytes)) };
  } catch (err) {
    got = { ok: false, error: err?.code ?? err?.name ?? String(err) };
  }
  const want = vector.expect;
  const pass = got.ok === want.ok
    && (got.ok ? JSON.stringify(got.value) === JSON.stringify(canonical(want.value)) : got.error === want.error);
  results.push({ id: vector.id, pass, got: summarize(got) });
}
process.stdout.write(JSON.stringify({ call: job.call, entry: job.entry, loaded: fn !== null, error: loadError, results }) + "\n");
