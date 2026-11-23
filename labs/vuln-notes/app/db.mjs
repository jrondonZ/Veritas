// Database location and seeding for the vuln-notes lab.
import { copyFileSync, existsSync } from "node:fs";
import { randomBytes, scryptSync } from "node:crypto";
import { DatabaseSync } from "node:sqlite";

export const DB_PATH = "/data/notes.db";
export const SNAPSHOT_DIR = "/data/snapshots";
// JSON lines, one per SQL statement the app runs: the statement text and its bound parameters, never
// results. It lives on its own volume, which the Veritas query-log sensor mounts read-only.
export const QUERY_LOG = "/logs/queries.jsonl";
// JSON lines, one per file the app opens, process it starts, or request it makes, written before the action. The
// Veritas activity-log sensor reads it from the same volume.
export const ACTIVITY_LOG = "/logs/activity.jsonl";
// Exports live here; the folder is empty in the lab, so every read fails cleanly.
export const EXPORTS = "/data/exports";

export function open() {
  return new DatabaseSync(DB_PATH);
}

function hashPassword(password) {
  const salt = randomBytes(16);
  return `scrypt$${salt.toString("hex")}$${scryptSync(password, salt, 32).toString("hex")}`;
}

// Synthetic identities. Every note body carries a per-identity canary so later
// oracles can tell, without judgment, whose data a response contains.
const USERS = [
  { email: "alice@lab.test", secretEnv: "VRT_ALICE", role: "user", canary: "alice" },
  { email: "bob@lab.test", secretEnv: "VRT_BOB", role: "user", canary: "bob" },
];

export function seedIfMissing() {
  if (existsSync(DB_PATH)) return false;
  const db = open();
  db.exec(`
    CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, password TEXT NOT NULL,
                        role TEXT NOT NULL, display_name TEXT NOT NULL);
    CREATE TABLE notes (id INTEGER PRIMARY KEY, owner_id INTEGER NOT NULL REFERENCES users(id),
                        title TEXT NOT NULL, body TEXT NOT NULL);
  `);
  const addUser = db.prepare("INSERT INTO users (email, password, role, display_name) VALUES (?, ?, ?, ?)");
  const addNote = db.prepare("INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)");
  for (const u of USERS) {
    const secret = process.env[u.secretEnv];
    if (!secret) throw new Error(`${u.secretEnv} is not set; start the lab with veritas lab up`);
    const { lastInsertRowid: userId } = addUser.run(u.email, hashPassword(secret), u.role, u.canary);
    for (let n = 1; n <= 3; n++) {
      addNote.run(userId, `${u.canary} note ${n}`, `vrt-seed-${u.canary}-${n}`);
    }
  }
  db.close();
  copyFileSync(DB_PATH, `${SNAPSHOT_DIR}/s-01.db`);
  return true;
}
