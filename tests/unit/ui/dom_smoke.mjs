// Runs the central page's own script against its embedded data, with a small stand-in for the DOM, and walks every
// view: the workspace, each run, each tab, every expandable row, the filters, and the copy buttons. Any exception
// fails the run. Usage: node dom_smoke.mjs path/to/index.html
import { readFileSync } from "node:fs";

const html = readFileSync(process.argv[2], "utf8");
const data = /<script type="application\/json" id="veritas-data">([\s\S]*?)<\/script>/.exec(html)[1];
const script = /<script>([\s\S]*?)<\/script>\s*<\/body>/.exec(html)[1];

class Node {}
class Text extends Node {
  constructor(text) { super(); this.textContent = text; }
}
class Element extends Node {
  constructor(tag) {
    super();
    Object.assign(this, { tag, children: [], attrs: {}, listeners: {}, hidden: false, className: "", value: "", own: "" });
    const set = new Set();
    this.classList = { add: (c) => set.add(c), remove: (c) => set.delete(c),
      toggle: (c, on) => ((on ?? !set.has(c)) ? set.add(c) : set.delete(c)) };
  }
  set textContent(text) { this.children = []; this.own = String(text); }
  get textContent() { return this.own + this.children.map((c) => c.textContent).join(""); }
  setAttribute(key, value) { if (key === "hidden") this.hidden = true; this.attrs[key] = String(value); }
  getAttribute(key) { return this.attrs[key]; }
  addEventListener(type, fn) { (this.listeners[type] ||= []).push(fn); }
  fire(type) { for (const fn of this.listeners[type] || []) fn({ key: "Enter", preventDefault() {} }); }
  append(...nodes) {
    for (const n of nodes) {
      if (!(n instanceof Node)) throw new Error(`appended a ${typeof n}, not a node`);
      this.children.push(n);
    }
  }
  replaceChildren(...nodes) { this.children = []; this.append(...nodes); }
  focus() {}
  scrollIntoView() {}
  all(test, out = []) {
    for (const c of this.children) if (c instanceof Element) { if (test(c)) out.push(c); c.all(test, out); }
    return out;
  }
}

const block = new Element("script");
block.own = data;
const fixed = { "veritas-data": block, main: new Element("main"), subnav: new Element("div"),
  stamp: new Element("span"), colophon: new Element("div") };
const listeners = {};
Object.assign(globalThis, {
  Node,
  document: { getElementById: (id) => fixed[id] ?? null, createElement: (tag) => new Element(tag),
    createTextNode: (text) => new Text(text), createRange: () => ({ selectNodeContents() {} }) },
  window: { addEventListener: (type, fn) => { (listeners[type] ||= []).push(fn); }, scrollTo() {}, print() {},
    matchMedia: () => ({ matches: false }), getSelection: () => ({ removeAllRanges() {}, addRange() {} }) },
  location: { hash: "#/" },
  setTimeout: (fn) => fn(),
});
Object.defineProperty(globalThis, "navigator", { value: { clipboard: { writeText: async () => {} } } });

new Function(script)();
const DATA = JSON.parse(data);
const main = fixed.main;
let views = 0;
const go = (hash) => { location.hash = hash; for (const fn of listeners.hashchange) fn(); views += 1; };
const exercise = () => {
  for (const row of main.all((e) => e.tag === "tr" && e.className === "row")) row.fire("click");
  for (const input of main.all((e) => e.tag === "input")) { input.value = "s-0 high"; input.fire("input"); }
  for (const select of main.all((e) => e.tag === "select")) {
    select.value = select.children[1]?.attrs.value ?? "";
    select.fire("change");
  }
  for (const button of main.all((e) => e.className === "copy")) button.fire("click");
};
views += 1;
exercise();
for (const run of DATA.overview.runs) {
  go(`#/run/${run.id}`);
  exercise();
  for (const tab of main.all((e) => e.attrs.role === "tab")) { tab.fire("click"); views += 1; exercise(); }
}
go("#/run/r-999999");  // a run older than the snapshot keeps
if (!main.textContent.includes("veritas show r-999999")) throw new Error("no fallback for a run outside the snapshot");
go("#/");
console.log(`ok ${views} views`);
