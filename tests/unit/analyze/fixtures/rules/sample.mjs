// Test fixture for the static security rules: one instance of each rule, next to the safe variant that must not
// be flagged. It is never run.
import { exec } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import { BrowserWindow, shell } from "electron";

export function handle(req, res) {
  eval(req.query.code); // dynamic-code
  exec(`convert ${req.query.file} out.png`); // shell-command
  exec("uptime"); // safe: a fixed command
  fs.readFileSync("/srv/files/" + req.query.name); // path-from-input
  fs.readFileSync("/srv/files/index.html"); // safe: a fixed path
  res.redirect(req.query.next); // redirect-from-input
  res.redirect("/home"); // safe: a fixed target
  console.error(`failed: ${new Error("x").stack}`); // safe: a log, not a response
  res.send(`<h1>${escapeHtml(req.query.q)}</h1>`); // safe: encoded
}

export function render(el, html) {
  el.innerHTML = html; // dom-html
  el.textContent = html; // safe
}

export function digest(data) {
  return crypto.createHash("md5").update(data).digest("hex"); // weak-hash
}

export function makeToken() {
  return Math.random().toString(36).slice(2); // weak-random
}

export function shuffle(items) {
  return items.sort(() => Math.random() - 0.5); // safe: not a security value
}

export const agent = { rejectUnauthorized: false }; // tls-unverified
const awsKey = "AKIAABCDEFGHIJKLMNOP"; // hardcoded-secret (a made-up value in the documented key format)

export function open(url) {
  shell.openExternal(url); // open-external
}

export function makeWindow() {
  return new BrowserWindow({ webPreferences: { nodeIntegration: true, contextIsolation: false, sandbox: true } });
}

function escapeHtml(text) {
  return String(text).replace(/[&<>"']/g, "");
}

export const used = awsKey.length;
