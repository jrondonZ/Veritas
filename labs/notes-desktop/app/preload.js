// notes-desktop preload script (lab app): the bridge the pages use to reach the main process.
const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("notes", {
  list: () => ipcRenderer.invoke("list-notes"),
  openLink: (url) => ipcRenderer.invoke("open-link", url),
  openHelp: () => ipcRenderer.invoke("open-help"),
  exportNote: (name, body) => ipcRenderer.invoke("export-note", name, body),
  exportSlot: (slot, body) => ipcRenderer.invoke("export-slot", slot, body),
});
