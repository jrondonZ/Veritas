// Writes the .lex sample files and the conformance vectors: `node labs/lexfmt/tools/make-samples.mjs`.
// This is the lab owner's tooling. It runs the owned library to record expected results. Veritas itself
// never executes the subject (the charter sets execute_subject: false).
import { mkdirSync, writeFileSync } from "node:fs";
import { readLex, writeLex } from "../dist/lexfmt.js";

const root = new URL("../", import.meta.url);
const samples = new URL("samples/", root);
mkdirSync(samples, { recursive: true });

function crc32(bytes, end) {
  let crc = 0xffffffff;
  for (let i = 0; i < end; i++) {
    crc ^= bytes[i];
    for (let k = 0; k < 8; k++) crc = crc & 1 ? 0xedb88320 ^ (crc >>> 1) : crc >>> 1;
  }
  return (crc ^ 0xffffffff) >>> 0;
}

// Rewrite the trailer so a deliberately damaged body still passes the checksum.
function reseal(bytes) {
  const out = Uint8Array.from(bytes);
  new DataView(out.buffer).setUint32(out.length - 4, crc32(out, out.length - 4), true);
  return out;
}

const metaText = writeLex({
  sections: [
    { type: 0x01, value: { title: "Quarterly plan", author: "lab" } },
    { type: 0x02, value: "Hello, lex." },
  ],
});

const cases = {
  minimal: writeLex({ sections: [] }),
  "meta-text": metaText,
  "readonly-blob": writeLex({ readonly: true, sections: [{ type: 0x03, flags: 0x01, value: [0, 1, 2, 250, 255] }] }),
  "template-flag-04": writeLex({ template: true, flags: 0x04, sections: [{ type: 0x02, value: "bit 0x04 rides along" }] }),
  "bad-magic": reseal(Uint8Array.from(metaText, (b, i) => (i === 0 ? 0x4d : b))),
  "bad-version": reseal(Uint8Array.from(metaText, (b, i) => (i === 4 ? 2 : b))),
  "bad-checksum": Uint8Array.from(metaText, (b, i) => (i === metaText.length - 1 ? b ^ 0xff : b)),
  "short": metaText.slice(0, 6),
  "truncated-payload": reseal(Uint8Array.of(...metaText.slice(0, metaText.length - 9), 0, 0, 0, 0)),
  "unknown-type": reseal(Uint8Array.from(metaText, (b, i) => (i === 12 ? 0x09 : b))),
  "reserved-bits": reseal(Uint8Array.from(metaText, (b, i) => (i === 14 ? 0x01 : b))),
  "trailing-data": reseal(Uint8Array.of(...metaText.slice(0, metaText.length - 4), 0xaa, 0, 0, 0, 0)),
};

const vectors = [];
for (const [name, bytes] of Object.entries(cases)) {
  writeFileSync(new URL(`${name}.lex`, samples), bytes);
  let expect;
  try {
    expect = { ok: true, value: readLex(bytes) };
  } catch (err) {
    expect = { ok: false, error: err.code ?? err.name };
  }
  vectors.push({ id: name, sample: `samples/${name}.lex`, expect });
}
// `call` names the exported function every vector exercises; an implementation must export it too.
writeFileSync(new URL("conformance.json", root), JSON.stringify({ version: 1, call: "readLex", vectors }, null, 2) + "\n");
console.log(`wrote ${vectors.length} samples and conformance.json`);
