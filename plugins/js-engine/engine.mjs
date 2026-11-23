// Veritas JavaScript engine core (docs/architecture.md §8.3): turns JavaScript files into Program Model facts.
// Node built-ins plus vendored acorn only. plugin.mjs runs it with no network and read-only inputs.
// License, DRM, and anti-tamper logic is excluded: such a function is reported by name and nothing inside
// it becomes a fact (§5.4).
//
// Security facts: request input is tracked through variables within a function (taint), and the places it
// reaches are recorded. These are HTML and SQL built as strings, code and command execution, file paths,
// redirects, and DOM writes. Error stacks in responses, cookie attributes, weak hashing, and disabled TLS
// checks are recorded too. The kernel's rules turn these into candidate findings.
import { createHash } from "node:crypto";
import { closeSync, fstatSync, openSync, readSync } from "node:fs";
import { isAbsolute, join, normalize, sep } from "node:path";
import { parse } from "./vendor/acorn.mjs";

export const VERSION = "0.0.1";
const INPUTS = process.env.VERITAS_INPUTS ?? "/inputs";
const MAX_FILE = 16 * 1024 * 1024; // one JavaScript file, alone or inside an archive
const MAX_SUBJECT = 256 * 1024 * 1024; // the charter's limit; an archive is read member by member, never whole
const MAX_INDEX = 32 * 1024 * 1024; // an archive's JSON index
const MAX_PAGE = 4 * 1024 * 1024;
const MAX_MEMBERS = 500; // the app's own code files analyzed per archive
const OUTPUT_BUDGET = 12 * 1024 * 1024; // facts for one archive stay under the plugin's 16 MiB output limit
const SAFE_NAME = /^[^/\\\u0000-\u001f\u007f]+$/;
const LIMITS = { strings: 2000, calls: 5000, numbers: 2000, reads: 2000, writes: 2000, templates: 2000, cookies: 500,
  sinks: 2000, crypto: 500, tls: 200 };
const MAX_STRING = 200;
const MAX_IDENTIFIERS = 10000;
const EXCLUDE = /licen[cs]e|serial.?(key|number)|activation|trial.?period|\bdrm\b|tamper|keygen|crack/i;
// Well-known algorithm constants (value -> name); naming one is an observed fact about the code.
const KNOWN = new Map([
  [0xedb88320, "CRC-32 (reflected IEEE 802.3 polynomial)"],
  [0x04c11db7, "CRC-32 (IEEE 802.3 polynomial, normal form)"],
  [0x82f63b78, "CRC-32C (reflected Castagnoli polynomial)"],
  [0x811c9dc5, "FNV-1a 32-bit offset basis"],
  [0x01000193, "FNV 32-bit prime"],
  [0x67452301, "MD5 and SHA-1 initial state word"],
  [0x6a09e667, "SHA-256 initial state word"],
  [0x9e3779b9, "golden-ratio constant (TEA, hashing)"],
]);
// DataView methods: [bytes, kind]
const VIEW_READ = { getUint8: [1, "u"], getInt8: [1, "i"], getUint16: [2, "u"], getInt16: [2, "i"], getUint32: [4, "u"],
  getInt32: [4, "i"], getFloat32: [4, "f"], getFloat64: [8, "f"], getBigUint64: [8, "u"], getBigInt64: [8, "i"] };
const VIEW_WRITE = Object.fromEntries(Object.entries(VIEW_READ).map(([k, v]) => [k.replace(/^get/, "set"), v]));
const BUFFER = /^(read|write)(U?)(Int|Float|Double|BigInt|BigUInt)(8|16|32|64)?(LE|BE)?$/;
const NETWORK = new Set(["fetch", "XMLHttpRequest", "WebSocket", "EventSource", "navigator.sendBeacon", "http.request",
  "http.get", "https.request", "https.get", "net.connect", "net.createConnection", "axios.get", "axios.post",
  "axios.request", "axios.put", "axios.delete"]);
const STORAGE = /^(localStorage|sessionStorage)\.(getItem|setItem|removeItem|clear)$|^indexedDB\.open$|^fs\.(readFile|readFileSync|writeFile|writeFileSync|appendFile|appendFileSync|createReadStream|createWriteStream|unlink|unlinkSync|readdir|readdirSync)$/;
const IPC = /^(ipcMain\.(handle|handleOnce|on|once)|ipcRenderer\.(invoke|send|sendSync|on|once)|contextBridge\.exposeInMainWorld|webContents\.send)$/;
// Request input: names that carry it, the keys destructured from a handler's argument, and browser sources.
const SOURCE_ROOTS = new Set(["req", "request"]);
const SOURCE_KEYS = new Set(["req", "request", "params", "query", "body", "headers", "cookies"]);
const BROWSER_SOURCES = /^(location\.(search|hash|href|pathname)|document\.(URL|documentURI|referrer|cookie)|window\.(name|location(\.(search|hash|href))?)|event\.data)$/;
const SANITIZER = /escape|encode|sanitiz|purify|^Number$|^parseInt$|^parseFloat$|^Boolean$/i;
const SQL_TEXT = /\b(select|insert|update|delete)\b[\s\S]*\b(from|into|set|where|values)\b/i;
const FS_PATH = /^(readFile|readFileSync|createReadStream|writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream|unlink|unlinkSync|readdir|readdirSync|open|openSync|rm|rmSync|stat|statSync|copyFile|copyFileSync)$/;

function render(node) {
  if (!node) return "?";
  if (node.type === "Identifier") return node.name;
  if (node.type === "ThisExpression") return "this";
  if (node.type === "Super") return "super";
  if (node.type === "MemberExpression" && !node.computed) return `${render(node.object)}.${node.property.name}`;
  if (node.type === "MemberExpression") return `${render(node.object)}[]`;
  if (node.type === "CallExpression") return `${render(node.callee)}()`;
  return `(${node.type})`;
}

function literalValue(node) {
  if (!node) return undefined;
  if (node.type === "Literal" && node.regex === undefined && typeof node.value !== "bigint") return node.value;
  if (node.type === "UnaryExpression" && node.operator === "-" && node.argument.type === "Literal") return -node.argument.value;
  if (node.type === "TemplateLiteral" && node.expressions.length === 0) return node.quasis[0].value.cooked;
  return undefined;
}

function objectLiteral(node) {
  if (node?.type === "CallExpression" && render(node.callee) === "Object.freeze") node = node.arguments[0];
  if (node?.type !== "ObjectExpression") return undefined;
  const out = {};
  for (const prop of node.properties) {
    if (prop.type !== "Property" || prop.computed) return undefined;
    const key = prop.key.type === "Identifier" ? prop.key.name : String(prop.key.value);
    const value = literalValue(prop.value);
    if (value === undefined) return undefined;
    out[key] = value;
  }
  return out;
}

// The literal-valued properties of an object literal, skipping the rest: `webPreferences` nearly always has a
// computed `preload` path next to the flags that matter.
function literalProps(node) {
  if (node?.type !== "ObjectExpression") return undefined;
  const out = {};
  for (const prop of node.properties) {
    if (prop.type !== "Property" || prop.computed) continue;
    const value = literalValue(prop.value);
    if (value !== undefined) out[prop.key.type === "Identifier" ? prop.key.name : String(prop.key.value)] = value;
  }
  return out;
}

function byteArray(node) {
  if (node?.type !== "ArrayExpression" || node.elements.length < 2) return undefined;
  const values = node.elements.map(literalValue);
  return values.every((v) => Number.isInteger(v) && v >= 0 && v <= 255) ? values : undefined;
}

function children(node, visit) {
  for (const key of Object.keys(node)) {
    if (key === "loc" || key === "start" || key === "end" || key === "type") continue;
    const value = node[key];
    if (Array.isArray(value)) for (const v of value) v && typeof v.type === "string" && visit(v);
    else if (value && typeof value.type === "string") visit(value);
  }
}

function isFunction(node) {
  return node.type === "FunctionDeclaration" || node.type === "FunctionExpression" || node.type === "ArrowFunctionExpression";
}

// Name functions the way people refer to them: declarations, `const f = () => ...`, Class.method, and the
// methods of an object literal (`const handlers = { search() {} }` names `handlers.search`).
function functionNames(ast) {
  const names = new Map();
  const visit = (node, owner) => {
    if (node.type === "FunctionDeclaration" && node.id) names.set(node, node.id.name);
    if (node.type === "VariableDeclarator" && node.id.type === "Identifier" && node.init) {
      if (isFunction(node.init)) names.set(node.init, node.id.name);
      if (node.init.type === "ObjectExpression") owner = node.id.name;
    }
    if ((node.type === "ClassDeclaration" || node.type === "ClassExpression") && node.id) owner = node.id.name;
    if (node.type === "MethodDefinition" && !node.computed) names.set(node.value, `${owner ?? "?"}.${node.key.name ?? node.key.value}`);
    if (node.type === "Property" && !node.computed && isFunction(node.value) && !names.has(node.value)) {
      const key = node.key.type === "Identifier" ? node.key.name : String(node.key.value);
      names.set(node.value, owner ? `${owner}.${key}` : key);
    }
    children(node, (child) => visit(child, isFunction(node) ? null : owner));
  };
  visit(ast, null);
  return names;
}

function excludedFunctions(ast, names) {
  const excluded = new Map(); // function node -> reason
  const visit = (node, current) => {
    if (isFunction(node) && names.has(node)) {
      current = node;
      if (EXCLUDE.test(names.get(node))) excluded.set(node, "license-like name");
    }
    if (current && !excluded.has(current) && node.type === "Literal" && typeof node.value === "string" && EXCLUDE.test(node.value)) {
      excluded.set(current, "license-like string");
    }
    children(node, (child) => visit(child, current));
  };
  visit(ast, null);
  return excluded;
}

function analyzeSource(source) {
  let ast;
  let parsed = "module";
  const comments = [];
  const options = { ecmaVersion: "latest", locations: true, allowHashBang: true, onComment: comments };
  try {
    ast = parse(source, { ...options, sourceType: "module" });
  } catch {
    parsed = "script";
    ast = parse(source, { ...options, sourceType: "script", allowReturnOutsideFunction: true });
  }
  const names = functionNames(ast);
  const excludedNodes = excludedFunctions(ast, names);
  const facts = {
    parsed, functions: [], exports: [], classes: [], constants: {}, calls: [], reads: [], writes: [], byte_compares: [],
    throws: [], switches: [], strings: [], numbers: [], imports: [], network: [], storage: [], ipc: [],
    webpreferences: [], templates: [], cookies: [], sinks: [], crypto: [], tls: [], excluded: [], truncated: {},
    source_map: null, minified_hint: false,
  };
  const push = (kind, item) => {
    const limit = LIMITS[kind];
    if (limit !== undefined && facts[kind].length >= limit) {
      facts.truncated[kind] = (facts.truncated[kind] ?? 0) + 1;
      return;
    }
    facts[kind].push(item);
  };
  for (const comment of comments) {
    const m = /^# sourceMappingURL=(\S+)/.exec(comment.value);
    if (m) facts.source_map = m[1].slice(0, 300);
  }
  for (const [node, reason] of excludedNodes) facts.excluded.push({ function: names.get(node) ?? "<anonymous>", reason });

  // Module-level constants: numbers, strings, byte arrays, and frozen object literals.
  for (const statement of ast.body) {
    const decl = statement.type === "ExportNamedDeclaration" ? statement.declaration : statement;
    if (decl?.type !== "VariableDeclaration" || decl.kind !== "const") continue;
    for (const d of decl.declarations) {
      if (d.id.type !== "Identifier") continue;
      const bytes = byteArray(d.init);
      const obj = objectLiteral(d.init);
      const value = literalValue(d.init);
      if (bytes) facts.constants[d.id.name] = { kind: "bytes", value: bytes };
      else if (obj) facts.constants[d.id.name] = { kind: "object", value: obj };
      else if (value !== undefined) facts.constants[d.id.name] = { kind: typeof value, value };
    }
  }
  const constant = (name) => facts.constants[name];
  const numberOf = (node) => {
    const v = literalValue(node);
    if (typeof v === "number") return v;
    if (node?.type === "Identifier" && constant(node.name)?.kind === "number") return constant(node.name).value;
    return undefined;
  };

  // Where an offset expression points: absolute, from the end, relative to a moving position, or computed.
  const locate = (node, locals) => {
    const n = numberOf(node);
    if (n !== undefined) return { absolute: n };
    if (node?.type === "Identifier") {
      const init = locals.get(node.name);
      if (init?.type === "BinaryExpression" && init.operator === "-" && render(init.left).endsWith(".length")) {
        const k = numberOf(init.right);
        if (k !== undefined) return { from_end: k };
      }
      return { relative: { base: node.name, delta: 0 } };
    }
    if (node?.type === "BinaryExpression" && node.operator === "+" && node.left.type === "Identifier") {
      const k = numberOf(node.right);
      if (k !== undefined) return { relative: { base: node.left.name, delta: k } };
    }
    return { computed: true };
  };

  // The buffer a read or write lands in: `new DataView(x.buffer)` resolves to x; a typed array or Buffer is itself.
  const viewOver = (object, locals) => {
    if (object?.type !== "Identifier") return null;
    const init = locals.get(object.name);
    if (init?.type === "NewExpression" && render(init.callee) === "DataView") {
      const target = init.arguments[0];
      if (target?.type === "MemberExpression" && !target.computed && target.property.name === "buffer"
          && target.object.type === "Identifier") return target.object.name;
      if (target?.type === "Identifier") return target.name;
      return null;
    }
    return object.name;
  };

  // Taint: is an expression derived from request input (or browser-controlled input) in this function?
  const taintOf = (node, ctx) => {
    if (!node) return null;
    switch (node.type) {
      case "Identifier":
        if (ctx.tainted?.has(node.name)) return "tainted";
        if (ctx.sanitized?.has(node.name)) return "sanitized";
        return SOURCE_ROOTS.has(node.name) ? "tainted" : null;
      case "Property": // a key is a name, not data
        return taintOf(node.value, ctx);
      case "MemberExpression":
        if (BROWSER_SOURCES.test(render(node))) return "tainted";
        return taintOf(node.object, ctx);
      case "CallExpression": {
        const callee = render(node.callee);
        if (/\.searchParams\.(get|getAll)$/.test(callee)) return "tainted";
        const inner = [...node.arguments, node.callee.type === "MemberExpression" ? node.callee.object : null]
          .map((a) => taintOf(a, ctx));
        if (SANITIZER.test(callee.split(".").pop())) return inner.includes("tainted") ? "sanitized" : null;
        return inner.includes("tainted") ? "tainted" : inner.includes("sanitized") ? "sanitized" : null;
      }
      case "ConditionalExpression": { // the test decides which branch is the value; it isn't part of it
        const parts = [taintOf(node.consequent, ctx), taintOf(node.alternate, ctx)];
        return parts.includes("tainted") ? "tainted" : parts.includes("sanitized") ? "sanitized" : null;
      }
      case "TemplateLiteral":
      case "BinaryExpression":
      case "LogicalExpression":
      case "AwaitExpression":
      case "ChainExpression":
      case "UnaryExpression":
      case "ParenthesizedExpression":
      case "SpreadElement":
      case "ArrayExpression":
      case "ObjectExpression":
      case "TaggedTemplateExpression":
      case "NewExpression": {
        const parts = [];
        children(node, (child) => parts.push(taintOf(child, ctx)));
        return parts.includes("tainted") ? "tainted" : parts.includes("sanitized") ? "sanitized" : null;
      }
      default:
        return null;
    }
  };
  // A file path's taint. It's taintOf, except that basename() makes input safe as a path (it can't add a directory
  // level), and a local variable is followed back to the expression that declared it.
  const pathTaint = (node, ctx, depth = 0) => {
    if (!node || depth > 8) return taintOf(node, ctx);
    if (node.type === "Identifier" && ctx.locals?.has(node.name)) return pathTaint(ctx.locals.get(node.name), ctx, depth + 1);
    const merge = (parts) => (parts.includes("tainted") ? "tainted" : parts.includes("sanitized") ? "sanitized" : null);
    if (node.type === "CallExpression") {
      const callee = render(node.callee);
      const last = callee.split(".").pop();
      if (last === "basename") return null;
      if (/\.searchParams\.(get|getAll)$/.test(callee)) return "tainted";
      const parts = [...node.arguments, node.callee.type === "MemberExpression" ? node.callee.object : null]
        .map((a) => pathTaint(a, ctx, depth + 1));
      if (SANITIZER.test(last)) return parts.includes("tainted") ? "sanitized" : null;
      return merge(parts);
    }
    if (node.type === "ConditionalExpression") return merge([pathTaint(node.consequent, ctx, depth + 1), pathTaint(node.alternate, ctx, depth + 1)]);
    if (["BinaryExpression", "LogicalExpression", "TemplateLiteral", "AwaitExpression"].includes(node.type)) {
      const parts = [];
      children(node, (child) => parts.push(pathTaint(child, ctx, depth + 1)));
      return merge(parts);
    }
    return taintOf(node, ctx);
  };
  const markBinding = (pattern, state, ctx) => {
    if (!ctx.tainted || !pattern) return;
    const names = [];
    const collect = (p) => {
      if (p.type === "Identifier") names.push(p.name);
      else if (p.type === "ObjectPattern") p.properties.forEach((q) => collect(q.type === "RestElement" ? q.argument : q.value));
      else if (p.type === "ArrayPattern") p.elements.forEach((q) => q && collect(q));
      else if (p.type === "AssignmentPattern") collect(p.left);
      else if (p.type === "RestElement") collect(p.argument);
    };
    collect(pattern);
    for (const name of names) {
      ctx.tainted.delete(name);
      ctx.sanitized.delete(name);
      if (state === "tainted") ctx.tainted.add(name);
      if (state === "sanitized") ctx.sanitized.add(name);
    }
  };
  // Request-shaped parameters are input: `req`, and `{ req, params, query, body, ... }` destructured from a handler's
  // argument. IPC handlers registered inline get their arguments after the event marked as input.
  const seedTaint = (node, ctx, ipc) => {
    node.params.forEach((p, i) => {
      if (p.type === "Identifier" && SOURCE_ROOTS.has(p.name)) ctx.tainted.add(p.name);
      if (p.type === "ObjectPattern") {
        for (const prop of p.properties) {
          const key = prop.type === "Property" && !prop.computed ? prop.key.name ?? prop.key.value : null;
          if (SOURCE_KEYS.has(key)) markBinding(prop.value, "tainted", ctx);
        }
      }
      if (ipc && i > 0) markBinding(p, "tainted", ctx);
    });
  };
  const isStack = (node) => node?.type === "MemberExpression" && !node.computed && node.property.name === "stack";
  const textOf = (node) => {
    if (node?.type === "TemplateLiteral") return node.quasis.map((q) => q.value.cooked ?? "").join("${}");
    const v = literalValue(node);
    return typeof v === "string" ? v : null;
  };
  // Flatten a `+` chain into its parts, so "SELECT ... " + x is seen as one string.
  const concatParts = (node, out = []) => {
    if (node.type === "BinaryExpression" && node.operator === "+") {
      concatParts(node.left, out);
      concatParts(node.right, out);
    } else out.push(node);
    return out;
  };
  const inChain = new WeakSet();
  // A string built from parts: record it when it looks like HTML or SQL, or when it carries an error stack.
  const recordString = (node, text, dynamic, ctx, form) => {
    const states = dynamic.map((p) => taintOf(p, ctx));
    const html = /<[a-zA-Z!/]/.test(text);
    const sqlish = SQL_TEXT.test(text);
    const stack = dynamic.some(isStack);
    if (html || sqlish || stack) {
      push("templates", { function: ctx.fn, line: node.loc.start.line, form, html, sql: sqlish, stack,
        tainted: states.includes("tainted"), sanitized: states.includes("sanitized"), text: text.slice(0, 160),
        in_call: ctx.call ?? null });
    }
  };
  // Static means fixed text: a string literal, a template with no `${}`, or a module-level string constant that no
  // local or parameter of this function shadows. Anything else is computed at run time.
  const isStatic = (node, ctx) => (node?.type === "Literal" && typeof node.value === "string")
    || (node?.type === "TemplateLiteral" && node.expressions.length === 0)
    || (node?.type === "Identifier" && constant(node.name)?.kind === "string" && !ctx.locals?.has(node.name)
      && !(ctx.record?.param_names ?? []).includes(node.name));
  const sink = (node, ctx, kind, arg) => {
    push("sinks", { function: ctx.fn, line: node.loc.start.line, sink: kind, dynamic: !isStatic(arg, ctx),
      tainted: taintOf(arg, ctx) === "tainted" });
  };
  // Inline handlers of IPC channels and window messages receive input from another process or origin.
  const inputHandlers = new WeakSet();
  const findHandlers = (node) => {
    if (node.type === "CallExpression") {
      const callee = render(node.callee);
      const handler = node.arguments[1];
      const registers = /^ipcMain\.(handle|handleOnce|on|once)$|^ipcRenderer\.(on|once)$/.test(callee)
        || (/addEventListener$/.test(callee) && literalValue(node.arguments[0]) === "message");
      if (registers && handler && isFunction(handler)) inputHandlers.add(handler);
    }
    children(node, findHandlers);
  };
  findHandlers(ast);
  const cookieFact = (node, valueNode, ctx, via) => {
    const text = textOf(valueNode);
    if (text === null) return;
    push("cookies", { function: ctx.fn, line: node.loc.start.line, via, text: text.slice(0, 200),
      httponly: /httponly/i.test(text), secure: /;\s*secure/i.test(text), samesite: /samesite/i.test(text),
      clearing: /max-age=0|expires=thu,\s*01 jan 1970/i.test(text) });
  };
  const childProcess = { names: new Set(), objects: new Set() };
  const fsModule = { names: new Set(), objects: new Set(["fs"]) };

  const shortNames = { short: 0, total: 0 };
  const identifiers = new Set(); // every name in the file; the spec gate keeps internal ones out of the clean room
  const visit = (node, ctx) => {
    if (isFunction(node)) {
      const name = names.get(node);
      if (excludedNodes.has(node)) return; // nothing inside excluded logic becomes a fact
      if (name) {
        const paramNames = node.params.filter((p) => p.type === "Identifier").map((p) => p.name);
        facts.functions.push({ name, params: node.params.length, param_names: paramNames, returns: [],
          async: Boolean(node.async), line: node.loc.start.line, start: node.start, end: node.end, calls: [] });
        // A closure sees the input its enclosing function holds.
        ctx = { fn: name, record: facts.functions[facts.functions.length - 1], locals: new Map(),
          tainted: new Set(ctx.tainted ?? []), sanitized: new Set(ctx.sanitized ?? []) };
      } else if (inputHandlers.has(node)) {
        ctx = { ...ctx, tainted: new Set(ctx.tainted ?? []), sanitized: new Set(ctx.sanitized ?? []) };
      }
      if (ctx.tainted) seedTaint(node, ctx, inputHandlers.has(node));
      if (ctx.call) ctx = { ...ctx, call: null }; // a callback's body isn't an argument of the call that took it
    }
    switch (node.type) {
      case "Identifier":
        shortNames.total++;
        if (node.name.length <= 2) shortNames.short++;
        if (identifiers.size < MAX_IDENTIFIERS) identifiers.add(node.name);
        break;
      case "VariableDeclarator": {
        if (node.id.type === "Identifier" && node.init && ctx.locals) ctx.locals.set(node.id.name, node.init);
        if (node.init && ctx.tainted) markBinding(node.id, taintOf(node.init, ctx), ctx);
        const required = node.init?.type === "CallExpression" && render(node.init.callee) === "require"
          ? literalValue(node.init.arguments[0]) : null;
        const bindings = /^(node:)?child_process$/.test(required ?? "") ? childProcess
          : /^(node:)?fs(\/promises)?$/.test(required ?? "") ? fsModule : null;
        if (bindings && node.id.type === "Identifier") bindings.objects.add(node.id.name);
        if (bindings && node.id.type === "ObjectPattern") {
          node.id.properties.forEach((p) => p.type === "Property" && p.value.type === "Identifier" && bindings.names.add(p.value.name));
        }
        break;
      }
      case "AssignmentExpression": {
        if (node.left.type === "Identifier" && ctx.tainted) markBinding(node.left, taintOf(node.right, ctx), ctx);
        const target = render(node.left);
        if (node.left.type === "MemberExpression" && !node.left.computed && /^(innerHTML|outerHTML)$/.test(node.left.property.name)) {
          sink(node, ctx, "dom-html", node.right);
        }
        if (/^(window\.)?location(\.href)?$/.test(target) && taintOf(node.right, ctx) === "tainted") sink(node, ctx, "redirect", node.right);
        if (target === "process.env.NODE_TLS_REJECT_UNAUTHORIZED") push("tls", { function: ctx.fn, line: node.loc.start.line, kind: "env" });
        break;
      }
      case "TemplateLiteral":
        recordString(node, textOf(node), node.expressions, ctx, "template");
        break;
      case "ReturnStatement":
        if (ctx.record && node.argument?.type === "Identifier") ctx.record.returns.push(node.argument.name);
        break;
      case "ClassDeclaration":
        if (node.id) facts.classes.push({ name: node.id.name, extends: node.superClass ? render(node.superClass) : null });
        break;
      case "ImportDeclaration": {
        facts.imports.push({ source: node.source.value, names: node.specifiers.map((s) => s.local.name) });
        const bindings = /^(node:)?child_process$/.test(node.source.value) ? childProcess
          : /^(node:)?fs(\/promises)?$/.test(node.source.value) ? fsModule : null;
        for (const s of bindings ? node.specifiers : []) {
          (s.type === "ImportSpecifier" ? bindings.names : bindings.objects).add(s.local.name);
        }
        break;
      }
      case "ImportExpression": {
        const v = literalValue(node.source);
        if (typeof v === "string") facts.imports.push({ source: v, names: [], dynamic: true });
        break;
      }
      case "Literal":
        if (typeof node.value === "string") {
          push("strings", { value: node.value.slice(0, MAX_STRING), offset: node.start, line: node.loc.start.line, function: ctx.fn });
        } else if (typeof node.value === "number" && (KNOWN.has(node.value >>> 0) || /^0x/i.test(node.raw))) {
          push("numbers", { value: node.value, raw: node.raw, known: KNOWN.get(node.value >>> 0) ?? null, line: node.loc.start.line,
            function: ctx.fn });
        }
        break;
      case "ThrowStatement":
        if (node.argument?.type === "NewExpression") {
          const args = node.argument.arguments.map(literalValue);
          push("throws", { function: ctx.fn, ctor: render(node.argument.callee),
            code: typeof args[0] === "string" && args.length > 1 ? args[0] : null, line: node.loc.start.line });
        }
        break;
      case "SwitchStatement": {
        const cases = node.cases.map((c) => {
          const called = [];
          const thrown = [];
          const collect = (n) => {
            if (n.type === "CallExpression" && n.callee.type === "Identifier") called.push(n.callee.name);
            if (n.type === "ThrowStatement" && n.argument?.type === "NewExpression") {
              const code = literalValue(n.argument.arguments[0]);
              if (typeof code === "string" && n.argument.arguments.length > 1) thrown.push(code);
            }
            if (!isFunction(n)) children(n, collect);
          };
          c.consequent.forEach(collect);
          return { value: c.test ? literalValue(c.test) ?? null : "default", calls: called, throws: thrown };
        });
        facts.switches.push({ function: ctx.fn, on: render(node.discriminant), cases });
        break;
      }
      case "BinaryExpression":
        if (["===", "!==", "==", "!="].includes(node.operator)) {
          for (const side of [node.left, node.right]) {
            if (side.type === "MemberExpression" && side.computed && side.object.type === "Identifier"
                && constant(side.object.name)?.kind === "bytes") {
              facts.byte_compares.push({ function: ctx.fn, constant: side.object.name });
            }
          }
        }
        if (node.operator === "+" && !inChain.has(node)) {
          const parts = concatParts(node);
          const walk = (n) => {
            if (n.type === "BinaryExpression" && n.operator === "+") {
              inChain.add(n);
              walk(n.left);
              walk(n.right);
            }
          };
          walk(node);
          if (parts.some((p) => typeof literalValue(p) === "string")) {
            const text = parts.map((p) => textOf(p) ?? "${}").join("");
            recordString(node, text, parts.filter((p) => textOf(p) === null), ctx, "concat");
          }
        }
        break;
      case "Property": {
        const key = node.computed ? null : node.key.type === "Identifier" ? node.key.name : String(node.key.value);
        if (key === "webPreferences") {
          const prefs = literalProps(node.value);
          if (prefs) facts.webpreferences.push({ function: ctx.fn, line: node.loc.start.line, prefs });
        }
        if (/^set-cookie$/i.test(key ?? "")) cookieFact(node, node.value, ctx, "header");
        if (key === "rejectUnauthorized" && literalValue(node.value) === false) {
          push("tls", { function: ctx.fn, line: node.loc.start.line, kind: "rejectUnauthorized" });
        }
        if (/^location$/i.test(key ?? "") && taintOf(node.value, ctx) === "tainted") sink(node, ctx, "redirect", node.value);
        break;
      }
      case "NewExpression":
      case "CallExpression": {
        const callee = render(node.callee);
        const args = node.arguments;
        const first = literalValue(args[0]);
        if (node.type === "CallExpression") {
          push("calls", { function: ctx.fn, callee, line: node.loc.start.line });
          if (ctx.record && node.callee.type === "Identifier") ctx.record.calls.push(node.callee.name);
          if (callee === "require" && typeof first === "string") facts.imports.push({ source: first, names: [], require: true });
        }
        const method = node.callee.type === "MemberExpression" && !node.callee.computed ? node.callee.property.name : null;
        const locals = ctx.locals ?? new Map();
        const over = method ? viewOver(node.callee.object, locals) : null;
        if (method && Object.hasOwn(VIEW_READ, method) && node.type === "CallExpression") {
          const [width, kind] = VIEW_READ[method];
          push("reads", { function: ctx.fn, api: "DataView", over, width, kind,
            little_endian: width === 1 ? null : literalValue(args[1]) === true, at: locate(args[0], locals), line: node.loc.start.line });
        } else if (method && Object.hasOwn(VIEW_WRITE, method) && node.type === "CallExpression") {
          const [width, kind] = VIEW_WRITE[method];
          push("writes", { function: ctx.fn, api: "DataView", over, width, kind,
            little_endian: width === 1 ? null : literalValue(args[2]) === true, at: locate(args[0], locals), line: node.loc.start.line });
        } else if (method && BUFFER.test(method) && node.type === "CallExpression") {
          const [, op, unsigned, type, bits, order] = BUFFER.exec(method);
          const entry = { function: ctx.fn, api: "Buffer", over, width: Number(bits ?? (type === "Double" ? 64 : 32)) / 8,
            kind: type === "Float" || type === "Double" ? "f" : unsigned ? "u" : "i", little_endian: order ? order === "LE" : null,
            at: locate(op === "read" ? args[0] : args[1], locals), line: node.loc.start.line };
          push(op === "read" ? "reads" : "writes", entry);
        } else if (method === "set" && args.length === 2 && args[0].type === "Identifier" && constant(args[0].name)?.kind === "bytes") {
          push("writes", { function: ctx.fn, api: "TypedArray.set", over, constant: args[0].name, at: locate(args[1], locals),
            line: node.loc.start.line });
        }
        if (NETWORK.has(callee)) push("network", { function: ctx.fn, api: callee, target: typeof first === "string" ? first.slice(0, 300) : null });
        if (STORAGE.test(callee)) push("storage", { function: ctx.fn, api: callee, key: typeof first === "string" ? first.slice(0, 200) : null });
        if (IPC.test(callee)) push("ipc", { function: ctx.fn, api: callee, channel: typeof first === "string" ? first.slice(0, 200) : null });
        // Security sinks: where input could be executed, written as markup, used as a path, or followed.
        const root = node.callee.type === "MemberExpression" ? render(node.callee.object) : null;
        if (callee === "eval") sink(node, ctx, "eval", args[0]);
        if (callee === "Function") sink(node, ctx, "function-constructor", args[args.length - 1]);
        if (/^(setTimeout|setInterval)$/.test(callee) && textOf(args[0]) !== null) sink(node, ctx, "eval-string", args[0]);
        if (/^vm\.(runInContext|runInNewContext|runInThisContext|compileFunction|Script)$/.test(callee)) sink(node, ctx, "vm", args[0]);
        const cpCall = (method && childProcess.objects.has(root)) ? method : childProcess.names.has(callee) ? callee : null;
        if (cpCall && /^(exec|execSync)$/.test(cpCall)) sink(node, ctx, "exec", args[0]);
        if (cpCall && /^(spawn|spawnSync|execFile|execFileSync)$/.test(cpCall)
            && args.some((a) => literalProps(a)?.shell === true)) sink(node, ctx, "shell", args[0]);
        const fsCall = (method && fsModule.objects.has(root)) ? method : fsModule.names.has(callee) ? callee : null;
        if (fsCall && FS_PATH.test(fsCall) && pathTaint(args[0], ctx) === "tainted") sink(node, ctx, "fs-path", args[0]);
        if (NETWORK.has(callee) && taintOf(args[0], ctx) === "tainted") sink(node, ctx, "request", args[0]);
        if (method === "redirect" && taintOf(args[args.length - 1], ctx) === "tainted") sink(node, ctx, "redirect", args[args.length - 1]);
        if (/^document\.(write|writeln)$/.test(callee)) sink(node, ctx, "dom-html", args[0]);
        if (method === "insertAdjacentHTML") sink(node, ctx, "dom-html", args[1]);
        if (callee === "shell.openExternal") sink(node, ctx, "open-external", args[0]);
        if (method === "setHeader" && /^set-cookie$/i.test(String(first))) cookieFact(node, args[1], ctx, "setHeader");
        if ((method === "createHash" || method === "createHmac" || callee === "createHash" || callee === "createHmac")
            && /^(md4|md5|sha1)$/i.test(String(first))) push("crypto", { function: ctx.fn, line: node.loc.start.line, algorithm: String(first).toLowerCase() });
        if (callee === "Math.random") push("crypto", { function: ctx.fn, line: node.loc.start.line, algorithm: "Math.random" });
        break;
      }
      case "ExportNamedDeclaration": {
        const d = node.declaration;
        if (d?.type === "FunctionDeclaration") facts.exports.push({ name: d.id.name, kind: "function", params: d.params.length });
        else if (d?.type === "ClassDeclaration") facts.exports.push({ name: d.id.name, kind: "class", extends: d.superClass ? render(d.superClass) : null });
        else if (d?.type === "VariableDeclaration") {
          for (const v of d.declarations) {
            if (v.id.type !== "Identifier") continue;
            const members = objectLiteral(v.init);
            facts.exports.push(members ? { name: v.id.name, kind: "object", members } : { name: v.id.name, kind: isFunction(v.init ?? {}) ? "function" : "value",
              ...(v.init && isFunction(v.init) ? { params: v.init.params.length } : {}) });
          }
        }
        for (const s of node.specifiers ?? []) facts.exports.push({ name: s.exported.name ?? s.exported.value, kind: "binding", local: s.local.name });
        break;
      }
      case "ExportDefaultDeclaration":
        facts.exports.push({ name: "default", kind: node.declaration.type === "ClassDeclaration" ? "class" : isFunction(node.declaration) ? "function" : "value" });
        break;
      default:
        break;
    }
    // Arguments of a call know which call they're passed to (a stack in `send(...)` leaks; in `console.error` it doesn't).
    const inner = node.type === "CallExpression" || node.type === "NewExpression" ? { ...ctx, call: render(node.callee) } : ctx;
    children(node, (child) => visit(child, inner));
  };
  visit(ast, { fn: null, record: null, locals: null });
  facts.minified_hint = shortNames.total > 200 && shortNames.short / shortNames.total > 0.5;
  facts.identifiers = [...identifiers].sort();
  return facts;
}

function inputPath(relative) {
  if (typeof relative !== "string" || isAbsolute(relative) || normalize(relative).split(sep).includes("..")) {
    throw new Error(`refused input path ${JSON.stringify(relative)}`);
  }
  return join(INPUTS, relative);
}

// Read from an open file without loading all of it: archives can be far larger than the code worth reading.
function readRange(fd, start, length) {
  const buf = Buffer.alloc(length);
  for (let done = 0; done < length; ) {
    const n = readSync(fd, buf, done, length - done, start + done);
    if (n === 0) throw new Error("the file ended early");
    done += n;
  }
  return buf;
}

function hashFile(fd, size) {
  const hash = createHash("sha256");
  const chunk = Buffer.alloc(1 << 20);
  for (let pos = 0; pos < size; ) {
    const n = readSync(fd, chunk, 0, Math.min(chunk.length, size - pos), pos);
    if (n === 0) throw new Error("the file ended early");
    hash.update(chunk.subarray(0, n));
    pos += n;
  }
  return hash.digest("hex");
}

const sha256Of = (data) => createHash("sha256").update(data).digest("hex");
const failure = (err) => {
  // A SyntaxError comes from the parser and means the file isn't JavaScript we can read; anything else is a bug
  // in this engine, reported with where it happened.
  const where = err instanceof SyntaxError ? "" : ` (engine.mjs${/engine\.mjs(:\d+:\d+)/.exec(err.stack ?? "")?.[1] ?? ""})`;
  return `${err instanceof SyntaxError ? "parse failed" : "analysis failed"}: ${String(err.message).slice(0, 200)}${where}`;
};

// Electron's archive format: a uint32 4, the header pickle's size, that pickle's payload size, the JSON index's
// length, then the index. File contents follow the header, at offsets counted from its end.
function asarIndex(fd, size) {
  if (size < 16) return null;
  const head = readRange(fd, 0, 16);
  if (head.readUInt32LE(0) !== 4) return null;
  const headerSize = head.readUInt32LE(4);
  const jsonSize = head.readUInt32LE(12);
  if (jsonSize > MAX_INDEX || jsonSize + 8 > headerSize || 8 + headerSize > size) return null;
  let index;
  try {
    index = JSON.parse(readRange(fd, 16, jsonSize).toString("utf8"));
  } catch {
    return null;
  }
  if (!index || typeof index.files !== "object" || index.files === null) return null;
  const base = 8 + headerSize;
  const out = { entries: [], unpacked: 0, refused: 0 };
  const walk = (node, prefix, depth) => {
    for (const [name, entry] of Object.entries(node.files)) {
      const path = prefix ? `${prefix}/${name}` : name;
      // Names come from the subject. One that could step out of its directory, or a tree this deep, is refused and
      // counted, so nothing is left out silently.
      if (!SAFE_NAME.test(name) || name === "." || name === ".." || path.length > 1024 || depth > 64
          || !entry || typeof entry !== "object") {
        out.refused++;
        continue;
      }
      if (entry.files && typeof entry.files === "object") walk(entry, path, depth + 1);
      else if (entry.unpacked) out.unpacked++; // stored next to the archive, not in it
      else if (entry.link === undefined) {
        const offset = Number(entry.offset);
        const length = Number(entry.size);
        if (Number.isSafeInteger(offset) && offset >= 0 && Number.isSafeInteger(length) && length >= 0
            && base + offset + length <= size) out.entries.push({ path, start: base + offset, size: length });
        else out.refused++;
      }
    }
  };
  walk(index, "", 0);
  out.entries.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  return out;
}

const DEPENDENCY = /(^|\/)node_modules\/(@[^/]+\/)?[^/]+\/package\.json$/;

// An Electron app: analyze its own code, check its pages, and inventory (not analyze) the bundled dependencies by
// name and version. Members are read one at a time, so memory stays near the size of the largest.
function analyzeArchive(fd, index) {
  const out = { archive: "asar", members: [], pages: [], dependencies: [], package: null, csp_in_code: false,
    entries: index.entries.length, unpacked: index.unpacked, refused: index.refused,
    skipped: { too_large: 0, limit: 0 } };
  const seen = new Set();
  let budget = OUTPUT_BUDGET;
  for (const e of index.entries) {
    const dependency = DEPENDENCY.test(e.path);
    const code = !dependency && !/(^|\/)node_modules\//.test(e.path) && /\.(m?js|cjs)$/i.test(e.path);
    const page = !dependency && !/(^|\/)node_modules\//.test(e.path) && /\.html?$/i.test(e.path);
    if (!(dependency || code || page || e.path === "package.json")) continue;
    if (e.size > (code ? MAX_FILE : MAX_PAGE)) {
      out.skipped.too_large++;
      continue;
    }
    const data = readRange(fd, e.start, e.size);
    const text = data.toString("utf8");
    if (e.path === "package.json" || dependency) {
      let pkg = null;
      try {
        pkg = JSON.parse(text);
      } catch {
        // an unreadable manifest is left out, not guessed at
      }
      const str = (v, n) => (typeof v === "string" ? v.slice(0, n) : null);
      if (e.path === "package.json") out.package = pkg ? { name: str(pkg.name, 214), version: str(pkg.version, 64), main: str(pkg.main, 256) } : null;
      else if (pkg && str(pkg.name, 214) && !seen.has(`${pkg.name}@${pkg.version}`)) {
        seen.add(`${pkg.name}@${pkg.version}`);
        out.dependencies.push({ name: str(pkg.name, 214), version: str(pkg.version, 64), path: e.path });
      }
    } else if (page) {
      out.pages.push({ path: e.path, sha256: sha256Of(data),
        csp: /<meta[^>]+http-equiv\s*=\s*["']?content-security-policy/i.test(text),
        // a <webview> attribute enables the feature by being present, whatever value it's given
        webview_node: /<webview\b[^>]*\snodeintegration\b/i.test(text),
        webview_websecurity: /<webview\b[^>]*\sdisablewebsecurity\b/i.test(text) });
    } else if (out.members.length >= MAX_MEMBERS || budget <= 0) {
      out.skipped.limit++;
    } else {
      if (/content-security-policy/i.test(text)) out.csp_in_code = true; // set as a header, perhaps
      let member;
      try {
        member = { path: e.path, offset: e.start, size: e.size, sha256: sha256Of(data), ...analyzeSource(text) };
      } catch (err) {
        member = { path: e.path, offset: e.start, size: e.size, sha256: sha256Of(data), error: failure(err) };
      }
      budget -= JSON.stringify(member).length;
      if (budget < 0) out.skipped.limit++;
      else out.members.push(member);
    }
  }
  out.dependencies.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : a.version < b.version ? -1 : 1));
  return out;
}

export function analyzeFile(file) {
  const path = inputPath(file.path);
  const fd = openSync(path, "r");
  try {
    const size = fstatSync(fd).size;
    if (size > MAX_SUBJECT) return { path: file.path, error: `larger than ${MAX_SUBJECT} bytes` };
    const sha256 = hashFile(fd, size);
    if (file.sha256 && file.sha256 !== sha256) return { path: file.path, sha256, error: "content does not match the pinned sha256" };
    const head = { path: file.path, sha256, bytes: size, engine: `veritas.engine.js@${VERSION}` };
    const index = asarIndex(fd, size);
    if (index) return { ...head, ...analyzeArchive(fd, index) };
    if (size > MAX_FILE) return { path: file.path, sha256, error: `larger than ${MAX_FILE} bytes` };
    try {
      return { ...head, ...analyzeSource(readRange(fd, 0, size).toString("utf8")) };
    } catch (err) {
      return { path: file.path, sha256, error: failure(err) };
    }
  } finally {
    closeSync(fd);
  }
}
