// notes-desktop: the Electron main process of an INTENTIONALLY VULNERABLE lab app.
// Veritas only reads this code (packed into dist/app.asar); it is never run. Each planted weakness has an ID
// that expected-code-findings.yaml lists, next to a correct look-alike that must stay quiet.
const { app, BrowserWindow, ipcMain, shell } = require("electron");
const { exec, execFile } = require("child_process");
const fs = require("fs");
const path = require("path");

const EXPORT_DIR = path.join(app.getPath("documents"), "notes-export");
const HELP_URL = "https://example.com/notes-desktop/help";
const SLOTS = Object.freeze({ daily: "daily.md", weekly: "weekly.md" });

// D1, D2: the page gets Node.js, and page scripts share the preload script's context.
function createMainWindow() {
  const win = new BrowserWindow({
    width: 1000,
    height: 700,
    webPreferences: { preload: path.join(__dirname, "preload.js"), nodeIntegration: true, contextIsolation: false },
  });
  win.loadFile("index.html");
  return win;
}

// D3, D4: no renderer sandbox and no same-origin policy for previews of untrusted notes.
function createPreviewWindow() {
  const win = new BrowserWindow({ webPreferences: { sandbox: false, webSecurity: false } });
  win.loadFile("viewer.html");
  return win;
}

// Look-alike: the secure settings, spelled out.
function createAboutWindow() {
  const win = new BrowserWindow({
    webPreferences: { preload: path.join(__dirname, "preload.js"), nodeIntegration: false, contextIsolation: true,
      sandbox: true, webSecurity: true },
  });
  win.loadFile("about.html");
  return win;
}

// D5: any URL the renderer sends is opened by the operating system.
function registerOpenLink() {
  ipcMain.handle("open-link", (event, url) => shell.openExternal(url));
}

// Look-alike: a fixed URL.
function registerOpenHelp() {
  ipcMain.handle("open-help", () => shell.openExternal(HELP_URL));
}

// D6: a file name from the renderer becomes a path, so "../" escapes the export folder.
function registerExport() {
  ipcMain.handle("export-note", (event, name, body) => {
    fs.writeFileSync(path.join(EXPORT_DIR, name), body);
  });
}

// Look-alike: the renderer picks a slot by ID, and the file names are fixed.
function registerExportSlot() {
  ipcMain.handle("export-slot", (event, slot, body) => {
    const file = SLOTS[slot];
    if (!file) throw new Error("unknown slot");
    fs.writeFileSync(path.join(EXPORT_DIR, file), body);
  });
}

// D7: the file name goes into a shell command line.
function registerReveal() {
  ipcMain.handle("reveal", (event, file) => exec(`xdg-open "${path.join(EXPORT_DIR, file)}"`));
}

// Look-alike: the program and its argument are passed separately, with no shell.
function registerRevealSafe() {
  ipcMain.handle("reveal-v2", (event, slot) => execFile("xdg-open", [path.join(EXPORT_DIR, SLOTS[slot] ?? "")]));
}

app.whenReady().then(() => {
  registerOpenLink();
  registerOpenHelp();
  registerExport();
  registerExportSlot();
  registerReveal();
  registerRevealSafe();
  createMainWindow();
});

module.exports = { createAboutWindow, createPreviewWindow };
