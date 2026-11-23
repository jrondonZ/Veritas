// Writes recordings/browse.har: `node labs/vuln-notes/tools/make-recording.mjs`.
// A browsing session on the lab, laid out the way a browser's HAR export records one: sign in, read and add notes,
// search, a failed note upload, a profile edit, and sign out, plus a stylesheet from another origin. It's written
// from the lab's own responses (app/server.mjs) rather than captured live, so it needs no running lab. Every
// credential in it is fake and starts with `vrt-fake-`; the tests check that none survives into anything Veritas
// stores.
import { mkdirSync, writeFileSync } from "node:fs";

const ORIGIN = "http://vuln-notes:8080";
const SID = "vrt-fake-sid-6f1c2a9e4b7d0e15";
const PASSWORD = "vrt-fake-password-alice";
const STATUS = { 200: "OK", 201: "Created", 500: "Internal Server Error" };
const page = (title, main) => `<!doctype html><html><head><meta charset="utf-8"><title>${title}</title></head>` +
  `<body>${main}</body></html>`;
const cookie = [{ name: "Cookie", value: `sid=${SID}` }];
const form = (fields) => ({
  mimeType: "application/x-www-form-urlencoded",
  text: new URLSearchParams(fields).toString(),
  params: Object.entries(fields).map(([name, value]) => ({ name, value })),
});
const stack = "Internal Server Error\nSyntaxError: Unterminated string in JSON at position 20\n" +
  "    at JSON.parse (<anonymous>)\n    at parseInput (file:///app/server.mjs:72:17)\n" +
  "    at Object.createNote (file:///app/server.mjs:146:15)\n";

let n = 0;
function entry(method, url, { send = [], post, status = 200, type = "application/json", body = "", got = [] } = {}) {
  const parsed = new URL(url, ORIGIN);
  const sentCookies = send.filter((h) => h.name === "Cookie").flatMap((h) => h.value.split("; "))
    .map((pair) => ({ name: pair.split("=")[0], value: pair.split("=").slice(1).join("=") }));
  n += 1;
  return {
    startedDateTime: new Date(Date.UTC(2026, 10, 19, 12, 0, n)).toISOString(),
    time: 4,
    request: {
      method, url: parsed.href, httpVersion: "HTTP/1.1",
      headers: [{ name: "Host", value: parsed.host }, { name: "User-Agent", value: "Mozilla/5.0 (lab recording)" },
        ...(post ? [{ name: "Content-Type", value: post.mimeType }] : []), ...send],
      queryString: [...parsed.searchParams].map(([name, value]) => ({ name, value })),
      cookies: sentCookies, headersSize: -1, bodySize: post ? post.text.length : 0,
      ...(post ? { postData: post } : {}),
    },
    response: {
      status, statusText: STATUS[status], httpVersion: "HTTP/1.1",
      headers: [{ name: "Content-Type", value: type }, { name: "Content-Length", value: String(Buffer.byteLength(body)) },
        ...(parsed.origin === ORIGIN ? [{ name: "X-Powered-By", value: "vuln-notes/1.0" }] : []), ...got],
      cookies: [], content: { size: Buffer.byteLength(body), mimeType: type, text: body },
      redirectURL: "", headersSize: -1, bodySize: Buffer.byteLength(body),
    },
    cache: {},
    timings: { send: 0, wait: 4, receive: 0 },
  };
}

const notes = [{ id: 1, title: "Buy milk", body: "2 litres" }, { id: 2, title: "Call bob", body: "about the lab" }];
const entries = [
  entry("GET", "/", { type: "text/html; charset=utf-8", body: page("vuln-notes", "<h1>vuln-notes</h1>") }),
  entry("GET", "https://cdn.example.net/lab/fonts.css", { type: "text/css", body: "body{font-family:serif}",
    got: [{ name: "Server", value: "ExampleCDN/2.1" }] }),
  entry("POST", "/api/login", { post: form({ email: "alice@lab.test", password: PASSWORD }),
    body: JSON.stringify({ ok: true }), got: [{ name: "Set-Cookie", value: `sid=${SID}; Path=/` }] }),
  entry("GET", "/api/notes", { send: cookie, body: JSON.stringify(notes) }),
  entry("GET", "/api/notes/2", { send: cookie, body: JSON.stringify(notes[1]) }),
  entry("GET", "/search?q=groceries", { type: "text/html; charset=utf-8",
    body: page("Search", "<p>Results for: groceries</p><p>No notes matched.</p>") }),
  entry("GET", "/search2?q=groceries", { type: "text/html; charset=utf-8",
    body: page("Search", "<p>Results for: groceries</p><p>No notes matched.</p>"),
    got: [{ name: "Content-Security-Policy", value: "default-src 'none'; frame-ancestors 'none'" }] }),
  entry("GET", "/api/search?q=milk", { send: cookie, body: JSON.stringify([{ id: 1, title: "Buy milk" }]) }),
  entry("POST", "/api/notes", { send: cookie, post: form({ title: "Lab report", body: "draft" }), status: 201,
    body: JSON.stringify({ id: 7 }) }),
  entry("POST", "/api/notes", { send: cookie, post: { mimeType: "application/json", text: '{"title": "unfinished' },
    status: 500, type: "text/plain; charset=utf-8", body: stack }),
  entry("PUT", "/api/profile", { send: cookie, post: { mimeType: "application/json", text: '{"display_name":"Alice"}' },
    body: JSON.stringify({ id: 1, email: "alice@lab.test", display_name: "Alice", role: "user" }) }),
  entry("GET", "/logout", { send: cookie, body: JSON.stringify({ ok: true }),
    got: [{ name: "Set-Cookie", value: "sid=; Path=/; Max-Age=0" }] }),
  entry("GET", "data:image/gif;base64,R0lGODlhAQABAAAAACw=", { type: "image/gif" }),
];

const har = { log: { version: "1.2", creator: { name: "Veritas lab recording", version: "1" }, pages: [], entries } };
mkdirSync(new URL("../recordings/", import.meta.url), { recursive: true });
writeFileSync(new URL("../recordings/browse.har", import.meta.url), `${JSON.stringify(har, null, 2)}\n`);
console.log(`recordings/browse.har: ${entries.length} entries`);
