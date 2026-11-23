// Restore a snapshot while the app is stopped: `node reset.mjs s-01`. The query and activity logs restart empty too.
import { copyFileSync, existsSync, rmSync, writeFileSync } from "node:fs";
import { ACTIVITY_LOG, DB_PATH, QUERY_LOG, SNAPSHOT_DIR } from "./db.mjs";

const name = process.argv[2] ?? "s-01";
if (!/^s-\d{2}$/.test(name)) throw new Error(`bad snapshot name: ${name}`);
const source = `${SNAPSHOT_DIR}/${name}.db`;
if (!existsSync(source)) throw new Error(`no such snapshot: ${name}`);
for (const suffix of ["-journal", "-wal", "-shm"]) rmSync(DB_PATH + suffix, { force: true });
copyFileSync(source, DB_PATH);
writeFileSync(QUERY_LOG, "");
writeFileSync(ACTIVITY_LOG, "");
console.log(`restored ${name}`);
