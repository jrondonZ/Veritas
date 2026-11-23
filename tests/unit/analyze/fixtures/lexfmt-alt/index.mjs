// Test fixture: an independent reader for the .lex format, written in a different style from the lab subject.
// It exercises the conformance harness and the similarity audit. It is not a clean-room artifact: its author
// also wrote the subject.
const fail = (code) => Object.assign(new Error(code), { code });
const utf8 = (part) => new TextDecoder("utf-8", { fatal: true }).decode(part);
const decoders = { 1: (part) => JSON.parse(utf8(part)), 2: utf8, 3: (part) => [...part] };

function checksum(data, length) {
  let value = ~0;
  for (let i = 0; i < length; i += 1) {
    value ^= data[i];
    for (let bit = 0; bit < 8; bit += 1) value = (value >>> 1) ^ (0xedb88320 & -(value & 1));
  }
  return ~value >>> 0;
}

export function readLex(bytes) {
  if (bytes.length < 16) throw fail("LEX_TRUNCATED");
  if (bytes[0] !== 0x4c || bytes[1] !== 0x45 || bytes[2] !== 0x58 || bytes[3] !== 0x01) throw fail("LEX_BAD_MAGIC");
  const le16 = (at) => bytes[at] | (bytes[at + 1] << 8);
  const le32 = (at) => (le16(at) | (le16(at + 2) << 16)) >>> 0;
  if (le16(4) !== 1) throw fail("LEX_VERSION");
  const bodyEnd = bytes.length - 4;
  if (checksum(bytes, bodyEnd) !== le32(bodyEnd)) throw fail("LEX_CHECKSUM");
  const flags = le16(6);
  const wanted = le32(8);
  const sections = [];
  let at = 12;
  while (sections.length < wanted) {
    if (at + 8 > bodyEnd) throw fail("LEX_TRUNCATED");
    if (le16(at + 2) !== 0) throw fail("LEX_RESERVED");
    const size = le32(at + 4);
    if (at + 8 + size > bodyEnd) throw fail("LEX_TRUNCATED");
    const decode = decoders[bytes[at]];
    if (!decode) throw fail("LEX_SECTION_TYPE");
    sections.push({ type: bytes[at], flags: bytes[at + 1], value: decode(bytes.subarray(at + 8, at + 8 + size)) });
    at += 8 + size;
  }
  if (at !== bodyEnd) throw fail("LEX_TRAILING");
  return { version: 1, flags, readonly: Boolean(flags & 1), template: Boolean(flags & 2), sections };
}
