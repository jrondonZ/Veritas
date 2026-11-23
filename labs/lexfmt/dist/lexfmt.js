// lexfmt 1.0.0: reader and writer for .lex project files (built bundle).
// Owned by the Veritas project. It is the demonstration subject for Analyze (labs/lexfmt/README.md).

const MAGIC = [0x4c, 0x45, 0x58, 0x01];
const VERSION = 1;
const HEADER_SIZE = 12;
const SECTION_HEADER_SIZE = 8;
const TRAILER_SIZE = 4;

export const SectionType = Object.freeze({ META: 0x01, TEXT: 0x02, BLOB: 0x03, LICENSE: 0x7f });
export const HeaderFlags = Object.freeze({ READONLY: 0x01, TEMPLATE: 0x02 });

export class LexError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "LexError";
    this.code = code;
  }
}

let crcTable = null;

function crc32(bytes, end) {
  if (crcTable === null) {
    crcTable = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      crcTable[n] = c >>> 0;
    }
  }
  let crc = 0xffffffff;
  for (let i = 0; i < end; i++) crc = crcTable[(crc ^ bytes[i]) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

// Section 0x7F carries a license key. Checking it is license logic.
function checkLicense(payload) {
  const key = new TextDecoder().decode(payload);
  const [serial, check] = key.split("-");
  let sum = 0;
  for (const ch of serial ?? "") sum = (sum * 31 + ch.charCodeAt(0)) % 9973;
  return String(sum).padStart(4, "0") === check;
}

function decodeText(payload) {
  return new TextDecoder("utf-8", { fatal: true }).decode(payload);
}

function decodeSection(type, payload) {
  switch (type) {
    case 0x01:
      return JSON.parse(decodeText(payload));
    case 0x02:
      return decodeText(payload);
    case 0x03:
      return Array.from(payload);
    case 0x7f:
      return { licensed: checkLicense(payload) };
    default:
      throw new LexError("LEX_SECTION_TYPE", `unknown section type ${type}`);
  }
}

function encodeSection(section, encoder) {
  let payload;
  switch (section.type) {
    case 0x01:
      payload = encoder.encode(JSON.stringify(section.value));
      break;
    case 0x02:
      payload = encoder.encode(String(section.value));
      break;
    case 0x03:
      payload = Uint8Array.from(section.value);
      break;
    default:
      throw new LexError("LEX_SECTION_TYPE", `cannot write section type ${section.type}`);
  }
  const out = new Uint8Array(SECTION_HEADER_SIZE + payload.length);
  const view = new DataView(out.buffer);
  view.setUint8(0, section.type);
  view.setUint8(1, section.flags ?? 0);
  view.setUint16(2, 0, true);
  view.setUint32(4, payload.length, true);
  out.set(payload, SECTION_HEADER_SIZE);
  return out;
}

export function readLex(bytes) {
  if (!(bytes instanceof Uint8Array)) throw new TypeError("readLex expects a Uint8Array");
  if (bytes.length < HEADER_SIZE + TRAILER_SIZE) throw new LexError("LEX_TRUNCATED", "file is shorter than its header");
  for (let i = 0; i < MAGIC.length; i++) {
    if (bytes[i] !== MAGIC[i]) throw new LexError("LEX_BAD_MAGIC", "not a .lex file");
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const version = view.getUint16(4, true);
  if (version !== VERSION) throw new LexError("LEX_VERSION", `unsupported version ${version}`);
  const flags = view.getUint16(6, true);
  const count = view.getUint32(8, true);
  const end = bytes.length - TRAILER_SIZE;
  const expected = view.getUint32(end, true);
  if (crc32(bytes, end) !== expected) throw new LexError("LEX_CHECKSUM", "checksum mismatch");
  const sections = [];
  let pos = HEADER_SIZE;
  for (let n = 0; n < count; n++) {
    if (pos + SECTION_HEADER_SIZE > end) throw new LexError("LEX_TRUNCATED", "section header runs past the end");
    const type = view.getUint8(pos);
    const sectionFlags = view.getUint8(pos + 1);
    const reserved = view.getUint16(pos + 2, true);
    if (reserved !== 0) throw new LexError("LEX_RESERVED", "reserved section bits are set");
    const length = view.getUint32(pos + 4, true);
    const start = pos + SECTION_HEADER_SIZE;
    if (start + length > end) throw new LexError("LEX_TRUNCATED", "section payload runs past the end");
    sections.push({ type, flags: sectionFlags, value: decodeSection(type, bytes.subarray(start, start + length)) });
    pos = start + length;
  }
  if (pos !== end) throw new LexError("LEX_TRAILING", "data after the last section");
  return {
    version,
    flags,
    readonly: (flags & HeaderFlags.READONLY) !== 0,
    template: (flags & HeaderFlags.TEMPLATE) !== 0,
    sections,
  };
}

export function writeLex(doc) {
  const encoder = new TextEncoder();
  const parts = (doc.sections ?? []).map((section) => encodeSection(section, encoder));
  const size = HEADER_SIZE + parts.reduce((total, part) => total + part.length, 0) + TRAILER_SIZE;
  const out = new Uint8Array(size);
  const view = new DataView(out.buffer);
  out.set(MAGIC, 0);
  view.setUint16(4, VERSION, true);
  view.setUint16(6, (doc.flags ?? 0) | (doc.readonly ? 0x01 : 0) | (doc.template ? 0x02 : 0), true);
  view.setUint32(8, parts.length, true);
  let pos = HEADER_SIZE;
  for (const part of parts) {
    out.set(part, pos);
    pos += part.length;
  }
  view.setUint32(pos, crc32(out, pos), true);
  return out;
}
