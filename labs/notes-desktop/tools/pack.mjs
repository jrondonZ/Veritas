// Packs app/ into dist/app.asar, the subject Veritas analyzes: `node labs/notes-desktop/tools/pack.mjs`.
// This is the lab owner's tooling, written here so the lab needs no npm packages. It writes Electron's archive
// layout (the one @electron/asar produces) with names sorted, so the same files always give the same bytes.
// The bundled dependencies are stand-ins with lab-only names, so the inventory has something to list.
import { createHash } from "node:crypto";
import { mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";

const root = new URL("../", import.meta.url);
const app = new URL("app/", root);

const manifest = (name, version) => `${JSON.stringify({ name, version, private: true }, null, 2)}\n`;
const BUNDLED = {
  "node_modules/lab-markdown/package.json": manifest("lab-markdown", "1.2.0"),
  // Dependency code is inventoried, not analyzed: this must not become a finding.
  "node_modules/lab-markdown/index.js": "module.exports = (source) => eval(source);\n",
  "node_modules/@lab/storage/package.json": manifest("@lab/storage", "0.3.1"),
  "node_modules/@lab/storage/node_modules/lab-markdown/package.json": manifest("lab-markdown", "0.9.4"),
};
// Stored next to the archive in app.asar.unpacked/, as native modules are; Veritas reports it as not analyzed.
const UNPACKED = { "native/helper.node": 4096 };

function walk(dir, prefix = "") {
  const out = [];
  for (const name of readdirSync(dir).sort()) {
    const url = new URL(name, dir);
    if (statSync(url).isDirectory()) out.push(...walk(new URL(`${name}/`, dir), `${prefix}${name}/`));
    else out.push([`${prefix}${name}`, readFileSync(url)]);
  }
  return out;
}

const files = [...walk(app), ...Object.entries(BUNDLED).map(([path, text]) => [path, Buffer.from(text, "utf8")])]
  .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));

const index = { files: {} };
const place = (path, entry) => {
  const parts = path.split("/");
  let node = index;
  for (const dir of parts.slice(0, -1)) node = (node.files[dir] ??= { files: {} });
  node.files[parts.at(-1)] = entry;
};
let offset = 0;
for (const [path, data] of files) {
  place(path, { size: data.length, offset: String(offset) });
  offset += data.length;
}
for (const [path, size] of Object.entries(UNPACKED)) place(path, { size, unpacked: true });

// Two pickles: the first holds the second's size; the second holds the JSON index, padded to 4 bytes.
const json = Buffer.from(JSON.stringify(index), "utf8");
const padding = (4 - (json.length % 4)) % 4;
const payload = 4 + json.length + padding;
const head = Buffer.alloc(16);
head.writeUInt32LE(4, 0);
head.writeUInt32LE(4 + payload, 4);
head.writeUInt32LE(payload, 8);
head.writeUInt32LE(json.length, 12);
const archive = Buffer.concat([head, json, Buffer.alloc(padding), ...files.map(([, data]) => data)]);

mkdirSync(new URL("dist/", root), { recursive: true });
writeFileSync(new URL("dist/app.asar", root), archive);
const digest = createHash("sha256").update(archive).digest("hex");
console.log(`dist/app.asar: ${files.length} files, ${archive.length} bytes, sha256 ${digest}`);
