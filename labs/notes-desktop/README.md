# notes-desktop lab

`notes-desktop` is a small note-taking app for Electron, written to be insecure. The Veritas project owns it. It exists so Analyze can be demonstrated and regression-tested on a packed desktop app. Analyze reads the app's `.asar` archive and finds weaknesses in its code, pages, and window settings. It also inventories the dependencies the archive bundles.

Veritas only reads this app. It never runs it, and the lab ships no Electron runtime. Don't install or run it either: the weaknesses are real.

## Authorization

The Veritas project owns this code. It may be analyzed by Veritas for security testing and regression tests. `veritas.charter.yaml` references this file, so its contents are hashed into the charter digest.

## Contents

- `app/` holds the app's source: the main process (`main.js`), the preload script, the renderer, and three pages.
- `tools/pack.mjs` is the lab owner's tooling. It packs `app/` into `dist/app.asar` in Electron's archive layout, with stand-in dependency manifests and one file marked as unpacked. It needs only Node.
- `dist/app.asar` is the subject. The charter pins it by SHA-256. Run the packer again after changing `app/`, then update the pin.
- `expected-code-findings.yaml` is the ground truth. Every candidate must be listed there, every listed item must be found, and nothing may be reported in a correct look-alike.
- `advisories/lab-osv.json` holds four stand-in advisories in the OSV format, about the lab-only packages. Import them with `veritas advisories import labs/notes-desktop/advisories/lab-osv.json`, then analyze again. The nested `lab-markdown` 0.9.4 should match one advisory (D11 in the ground truth). Nothing else should match: one advisory has a range the bundled version misses, one is withdrawn, and one is for another ecosystem.

## What the app contains, on purpose

| ID | Where | Weakness | Look-alike that must stay quiet |
|---|---|---|---|
| D1, D2 | `createMainWindow` | Node.js integration in the page, and no context isolation | `createAboutWindow` spells out the secure settings |
| D3, D4 | `createPreviewWindow` | no renderer sandbox, and web security off | |
| D5 | `registerOpenLink` | `shell.openExternal` opens any URL the renderer sends | `registerOpenHelp` opens a fixed URL |
| D6 | `registerExport` | a file name from the renderer becomes a path | `registerExportSlot` picks fixed names by ID |
| D7 | `registerReveal` | a file name goes into a shell command line | `registerRevealSafe` uses `execFile` and an argument array |
| D8 | `renderList` | note titles are written into the page as markup | `renderListSafe` builds text nodes |
| D9 | `index.html` | no Content-Security-Policy | `about.html` has one |
| D10 | `viewer.html` | `<webview nodeintegration="false">` turns Node.js on, because the attribute works by being present | `about.html` has a default `<webview>` |

The archive also carries three dependency manifests with lab-only names. A dependency file contains `eval`, and it must not become a finding, because dependency code is inventoried rather than analyzed. One file is marked unpacked, and the report must say it wasn't analyzed.
