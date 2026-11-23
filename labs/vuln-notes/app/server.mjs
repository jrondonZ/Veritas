// vuln-notes lab server. INTENTIONALLY VULNERABLE: each flaw marked "PLANTED Lx" (or Hx, for a missing response
// header) exists for Veritas demonstrations and regression tests (../expected-findings.yaml). "CONTROL Nx" routes
// do the same job correctly. Never expose this app outside its internal network.
import { exec, execFile } from "node:child_process";
import { createHash, randomBytes, scryptSync, timingSafeEqual } from "node:crypto";
import { appendFileSync, readFileSync } from "node:fs";
import { createServer } from "node:http";
import { basename, join } from "node:path";
import { ACTIVITY_LOG, EXPORTS, QUERY_LOG, open } from "./db.mjs";
import { OPENAPI } from "./openapi.mjs";

const db = open();
let querySeq = 0;
let activitySeq = 0;

// What the app is about to do, appended to the activity log before it does it.
function activity(entry) {
  appendFileSync(ACTIVITY_LOG, JSON.stringify({ seq: ++activitySeq, ts: new Date().toISOString(), ...entry }) + "\n");
}
// The lab never runs a real command: every shell gets /bin/false, which ignores its arguments and exits.
const NO_SHELL = { shell: "/bin/false", timeout: 2000 };
const FEEDS = Object.freeze({ status: "http://status.lab.invalid/feed.json" });

// A prepared statement that appends its SQL text and bound parameters to the query log before it runs.
// The write is synchronous, so the entry exists before the response is sent.
function logged(text) {
  const statement = db.prepare(text);
  const record = (params) =>
    appendFileSync(QUERY_LOG, JSON.stringify({ seq: ++querySeq, ts: new Date().toISOString(), sql: text, params }) + "\n");
  return {
    get: (...params) => (record(params), statement.get(...params)),
    all: (...params) => (record(params), statement.all(...params)),
    run: (...params) => (record(params), statement.run(...params)),
  };
}

const sql = {
  userByEmail: logged("SELECT * FROM users WHERE email = ?"),
  profile: logged("SELECT id, email, display_name, role FROM users WHERE id = ?"),
  notesByOwner: logged("SELECT id, title, body FROM notes WHERE owner_id = ? ORDER BY id"),
  noteById: logged("SELECT id, owner_id, title, body FROM notes WHERE id = ?"),
  insertNote: logged("INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)"),
  updateProfile: logged(
    "UPDATE users SET display_name = COALESCE(?, display_name), role = COALESCE(?, role) WHERE id = ?",
  ),
  searchNotes: logged("SELECT id, title FROM notes WHERE owner_id = ? AND title LIKE ? ORDER BY id"),
  // Not logged: Docker's health check polls these every two seconds.
  countNotes: db.prepare("SELECT COUNT(*) AS n FROM notes"),
  countUsers: db.prepare("SELECT COUNT(*) AS n FROM users"),
};
const sessions = new Map(); // session id -> user id; cleared whenever the lab restarts
const MAX_BODY = 64 * 1024;
const SELF = "http://vuln-notes:8080"; // the lab's own origin
const DESTINATIONS = Object.freeze({ notes: "/api/notes", search: "/search" });

// PLANTED H5, H6: no response sends X-Content-Type-Options, and every response names the app and its version.
function send(res, status, type, body, headers = {}) {
  res.writeHead(status, {
    "Content-Type": type,
    "Content-Length": Buffer.byteLength(body),
    "X-Powered-By": "vuln-notes/1.0",
    ...headers,
  });
  res.end(body);
}
const json = (res, status, value, headers) => send(res, status, "application/json", JSON.stringify(value), headers);
const escapeHtml = (text) =>
  text.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const page = (title, body) =>
  `<!doctype html><html><head><meta charset="utf-8"><title>${title}</title></head><body>${body}</body></html>`;

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY) reject(new Error("body too large"));
      else chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function parseInput(req, raw) {
  const type = (req.headers["content-type"] ?? "").split(";")[0].trim();
  if (type === "application/x-www-form-urlencoded") return Object.fromEntries(new URLSearchParams(raw));
  return JSON.parse(raw);
}

function currentUser(req) {
  for (const part of (req.headers.cookie ?? "").split(";")) {
    const [name, ...rest] = part.trim().split("=");
    if (name === "sid" && sessions.has(rest.join("="))) return { id: sessions.get(rest.join("=")) };
  }
  return null;
}

function verifyPassword(stored, password) {
  const [, saltHex, hashHex] = stored.split("$");
  const expected = Buffer.from(hashHex, "hex");
  const actual = scryptSync(password, Buffer.from(saltHex, "hex"), expected.length);
  return timingSafeEqual(expected, actual);
}

const index = page(
  "vuln-notes",
  "<h1>vuln-notes</h1><p>Intentionally vulnerable Veritas lab.</p>" +
    '<ul><li><a href="/search?q=notes">Search</a></li><li><a href="/search2?q=notes">Search (encoded)</a></li>' +
    '<li><a href="/openapi.json">API description</a></li><li><a href="/logout">Sign out</a></li>' +
    '<li><a href="https://docs.example.invalid/vuln-notes">External documentation</a></li></ul>' +
    '<form action="/search" method="get"><input name="q"><button>Search</button></form>' +
    '<form action="/api/notes" method="post"><input name="title"><input name="body"><button>Add</button></form>',
);

const handlers = {
  health: ({ res }) => json(res, 200, { ok: true, users: sql.countUsers.get().n, notes: sql.countNotes.get().n }),
  // PLANTED H1, H3: the front page sends no CSP and no framing protection.
  index: ({ res }) => send(res, 200, "text/html; charset=utf-8", index),
  openapi: ({ res }) => json(res, 200, OPENAPI),

  async login({ req, res }) {
    let input;
    try {
      input = parseInput(req, await readBody(req));
    } catch {
      return json(res, 400, { error: "invalid request" });
    }
    const user = sql.userByEmail.get(String(input.email ?? ""));
    if (!user || !verifyPassword(user.password, String(input.password ?? ""))) {
      return json(res, 401, { error: "invalid credentials" });
    }
    const sid = randomBytes(18).toString("base64url");
    sessions.set(sid, user.id);
    // PLANTED L3: the session cookie has neither HttpOnly nor SameSite.
    json(res, 200, { ok: true }, { "Set-Cookie": `sid=${sid}; Path=/` });
  },

  logout({ req, res }) {
    const user = currentUser(req);
    for (const [sid, id] of sessions) if (user && id === user.id) sessions.delete(sid);
    json(res, 200, { ok: true }, { "Set-Cookie": "sid=; Path=/; Max-Age=0" });
  },

  listNotes({ req, res, user }) {
    // CONTROL N6: only the lab's own origin may read the list across origins.
    const cors = req.headers.origin === SELF ? { "Access-Control-Allow-Origin": SELF, "Access-Control-Allow-Credentials": "true", Vary: "Origin" } : {};
    json(res, 200, sql.notesByOwner.all(user.id), cors);
  },

  getNote({ res, params }) {
    // PLANTED L1: any signed-in user can read any note; ownership is never checked.
    const note = sql.noteById.get(Number(params[0]));
    if (!note) return json(res, 404, { error: "not found" });
    json(res, 200, { id: note.id, title: note.title, body: note.body });
  },

  getNoteV2({ res, params, user }) {
    // CONTROL N1: the note must belong to the signed-in user.
    const note = sql.noteById.get(Number(params[0]));
    if (!note || note.owner_id !== user.id) return json(res, 404, { error: "not found" });
    json(res, 200, { id: note.id, title: note.title, body: note.body });
  },

  async createNote({ req, res, user }) {
    const raw = await readBody(req);
    let input;
    try {
      input = parseInput(req, raw);
    } catch (err) {
      // PLANTED L4: the parse error's stack trace is returned to the client.
      return send(res, 500, "text/plain; charset=utf-8", `Internal Server Error\n${err.stack}`);
    }
    // PLANTED L6: no anti-CSRF token and no Origin check, so form posts from any site are accepted.
    const { lastInsertRowid } = sql.insertNote.run(user.id, String(input.title ?? "untitled"), String(input.body ?? ""));
    json(res, 201, { id: Number(lastInsertRowid) });
  },

  async createNoteV2({ req, res, user }) {
    let input;
    try {
      input = JSON.parse(await readBody(req));
    } catch {
      return json(res, 400, { error: "invalid JSON" }); // CONTROL N3: a generic error
    }
    const { lastInsertRowid } = sql.insertNote.run(user.id, String(input.title ?? "untitled"), String(input.body ?? ""));
    json(res, 201, { id: Number(lastInsertRowid) });
  },

  getProfile({ req, res, user }) {
    // PLANTED L10: any origin may read the signed-in user's profile, because the request's Origin is echoed back
    // with credentials allowed.
    const cors = req.headers.origin ? { "Access-Control-Allow-Origin": req.headers.origin, "Access-Control-Allow-Credentials": "true" } : {};
    json(res, 200, sql.profile.get(user.id), cors);
  },

  async putProfile({ req, res, user }) {
    let input;
    try {
      input = JSON.parse(await readBody(req));
    } catch {
      return json(res, 400, { error: "invalid JSON" });
    }
    // PLANTED L5: role is written although the API documents only display_name.
    sql.updateProfile.run(input.display_name ?? null, input.role ?? null, user.id);
    json(res, 200, sql.profile.get(user.id));
  },

  async importNotes({ req, res }) {
    // PLANTED L8: always fails, with a body that depends on the input but has no error details.
    const ref = createHash("sha256").update(await readBody(req)).digest("hex").slice(0, 12);
    json(res, 500, { error: "import failed", ref });
  },

  search({ res, url }) {
    // PLANTED L2, H2, H4: the search term is written into the page without encoding, and neither a CSP nor
    // framing protection is sent.
    const term = url.searchParams.get("q") ?? "";
    send(res, 200, "text/html; charset=utf-8", page("Search", `<p>Results for: ${term}</p><p>No notes matched.</p>`));
  },

  search2({ res, url }) {
    // CONTROL N2, N7, N8: the term is HTML-encoded, and a restrictive CSP that also forbids framing is sent.
    const term = escapeHtml(url.searchParams.get("q") ?? "");
    send(res, 200, "text/html; charset=utf-8", page("Search", `<p>Results for: ${term}</p><p>No notes matched.</p>`), {
      "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    });
  },

  go({ res, url }) {
    // PLANTED L9: the browser is sent wherever `next` says, including other sites.
    const next = url.searchParams.get("next") ?? "/";
    res.writeHead(302, { Location: next, "Content-Length": 0 });
    res.end();
  },

  go2({ res, url }) {
    // CONTROL N5: `next` picks one of a fixed set of destinations on this site.
    const key = url.searchParams.get("next") ?? "";
    const target = Object.hasOwn(DESTINATIONS, key) ? DESTINATIONS[key] : "/";
    res.writeHead(302, { Location: target, "Content-Length": 0 });
    res.end();
  },

  readExport({ res, url }) {
    // PLANTED L11: the name becomes part of the path, so a name with "../" climbs out of the export folder.
    const file = join(EXPORTS, url.searchParams.get("name") ?? "");
    activity({ kind: "file", op: "read", path: file });
    try {
      json(res, 200, { found: true, text: readFileSync(file, "utf8").slice(0, 4096) });
    } catch {
      json(res, 200, { found: false });
    }
  },

  readExportV2({ res, url }) {
    // CONTROL N9: only the name's last segment is used, so the path stays in the export folder.
    const file = join(EXPORTS, basename(url.searchParams.get("name") ?? ""));
    activity({ kind: "file", op: "read", path: file });
    try {
      json(res, 200, { found: true, text: readFileSync(file, "utf8").slice(0, 4096) });
    } catch {
      json(res, 200, { found: false });
    }
  },

  thumbnail({ res, url }) {
    // PLANTED L12: the name is pasted into a shell command line. (The lab's shell is /bin/false, so nothing runs.)
    const command = `convert ${join(EXPORTS, url.searchParams.get("name") ?? "")} -resize 64x64 /tmp/thumb.png`;
    activity({ kind: "exec", shell: true, command });
    exec(command, NO_SHELL, () => json(res, 200, { queued: false, reason: "no thumbnailer in the lab" }));
  },

  thumbnailV2({ res, url }) {
    // CONTROL N10: the name is one argument of a program started without a shell.
    const args = [join(EXPORTS, basename(url.searchParams.get("name") ?? "")), "-resize", "64x64", "/tmp/thumb.png"];
    activity({ kind: "exec", shell: false, file: "convert", args });
    execFile("convert", args, { timeout: 2000 }, () => json(res, 200, { queued: false, reason: "no thumbnailer in the lab" }));
  },

  preview({ res, url }) {
    // PLANTED L13: the app fetches whatever URL it's given. (The request is aborted before it's sent.)
    const target = url.searchParams.get("url") ?? "";
    activity({ kind: "request", method: "GET", url: target });
    fetch(target, { signal: AbortSignal.abort() }).catch(() => {});
    json(res, 200, { preview: null, reason: "previews are off in the lab" });
  },

  previewV2({ res, url }) {
    // CONTROL N11: `feed` picks one of a fixed set of URLs.
    const key = url.searchParams.get("feed") ?? "";
    if (!Object.hasOwn(FEEDS, key)) return json(res, 200, { preview: null, reason: "unknown feed" });
    activity({ kind: "request", method: "GET", url: FEEDS[key] });
    fetch(FEEDS[key], { signal: AbortSignal.abort() }).catch(() => {});
    json(res, 200, { preview: null, reason: "previews are off in the lab" });
  },

  searchNotes({ res, url, user }) {
    // PLANTED L7: the search term is concatenated into the SQL text instead of being bound as a parameter.
    const term = url.searchParams.get("q") ?? "";
    const query = `SELECT id, title FROM notes WHERE owner_id = ${user.id} AND title LIKE '%${term}%' ORDER BY id`;
    json(res, 200, logged(query).all());
  },

  searchNotesV2({ res, url, user }) {
    // CONTROL N4: the same search, with the term bound as a parameter.
    json(res, 200, sql.searchNotes.all(user.id, `%${url.searchParams.get("q") ?? ""}%`));
  },
};

// [method, pattern, handler, requires a signed-in user]
const routes = [
  ["GET", /^\/health$/, handlers.health, false],
  ["GET", /^\/$/, handlers.index, false],
  ["GET", /^\/openapi\.json$/, handlers.openapi, false],
  ["POST", /^\/api\/login$/, handlers.login, false],
  ["GET", /^\/logout$/, handlers.logout, false],
  ["GET", /^\/api\/notes$/, handlers.listNotes, true],
  ["POST", /^\/api\/notes$/, handlers.createNote, true],
  ["GET", /^\/api\/notes\/(\d+)$/, handlers.getNote, true],
  ["POST", /^\/api\/v2\/notes$/, handlers.createNoteV2, true],
  ["GET", /^\/api\/v2\/notes\/(\d+)$/, handlers.getNoteV2, true],
  ["GET", /^\/api\/profile$/, handlers.getProfile, true],
  ["PUT", /^\/api\/profile$/, handlers.putProfile, true],
  ["POST", /^\/api\/import$/, handlers.importNotes, true],
  ["GET", /^\/api\/search$/, handlers.searchNotes, true],
  ["GET", /^\/api\/v2\/search$/, handlers.searchNotesV2, true],
  ["GET", /^\/search$/, handlers.search, false],
  ["GET", /^\/search2$/, handlers.search2, false],
  ["GET", /^\/go$/, handlers.go, false],
  ["GET", /^\/go2$/, handlers.go2, false],
  ["GET", /^\/api\/export$/, handlers.readExport, true],
  ["GET", /^\/api\/v2\/export$/, handlers.readExportV2, true],
  ["GET", /^\/api\/thumbnail$/, handlers.thumbnail, true],
  ["GET", /^\/api\/v2\/thumbnail$/, handlers.thumbnailV2, true],
  ["GET", /^\/api\/preview$/, handlers.preview, true],
  ["GET", /^\/api\/v2\/preview$/, handlers.previewV2, true],
];

async function handle(req, res) {
  const url = new URL(req.url, "http://lab");
  for (const [method, pattern, handler, needsUser] of routes) {
    const match = req.method === method && pattern.exec(url.pathname);
    if (!match) continue;
    const user = currentUser(req);
    if (needsUser && !user) return json(res, 401, { error: "sign in required" });
    return handler({ req, res, url, params: match.slice(1), user });
  }
  json(res, 404, { error: "not found" });
}

const server = createServer((req, res) => {
  handle(req, res).catch(() => {
    if (!res.headersSent) json(res, 500, { error: "internal error" });
  });
});
server.listen(8080, "0.0.0.0", () => console.log("vuln-notes listening on :8080"));
for (const sig of ["SIGTERM", "SIGINT"]) {
  process.on(sig, () =>
    server.close(() => {
      db.close();
      process.exit(0);
    }),
  );
}
