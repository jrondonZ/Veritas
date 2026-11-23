// Entry point: seed on first start (and take snapshot s-01), then serve.
import { seedIfMissing } from "./db.mjs";

if (seedIfMissing()) console.log("seeded synthetic identities; snapshot s-01 written");
await import("./server.mjs");
