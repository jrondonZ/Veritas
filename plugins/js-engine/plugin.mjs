// Veritas JavaScript engine plugin: the MCP-compatible stdio loop around engine.mjs (docs/architecture.md §6.3).
// It runs in the `engine` sandbox: no network, inputs mounted read-only, results returned as structured content.
import { createInterface } from "node:readline";
import { VERSION, analyzeFile } from "./engine.mjs";

const PROTOCOL_VERSION = "2025-06-18";
const TOOLS = [
  {
    name: "analyze",
    description: "Parse JavaScript files from the read-only inputs and return their Program Model facts.",
    inputSchema: {
      type: "object",
      properties: {
        files: {
          type: "array",
          maxItems: 200,
          items: {
            type: "object",
            properties: { path: { type: "string" }, sha256: { type: "string" } },
            required: ["path", "sha256"],
            additionalProperties: false,
          },
        },
      },
      required: ["files"],
      additionalProperties: false,
    },
    outputSchema: { type: "object", properties: { results: { type: "array" } }, required: ["results"] },
  },
];

function reply(id, result, error) {
  process.stdout.write(JSON.stringify(error ? { jsonrpc: "2.0", id, error } : { jsonrpc: "2.0", id, result }) + "\n");
}

const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
rl.on("line", (line) => {
  if (!line.trim()) return;
  const msg = JSON.parse(line);
  if (msg.id === undefined || msg.id === null) return; // notifications need no reply
  if (msg.method === "initialize") {
    reply(msg.id, {
      protocolVersion: PROTOCOL_VERSION,
      capabilities: { tools: {} },
      serverInfo: { name: "veritas-js-engine", version: VERSION },
    });
  } else if (msg.method === "tools/list") {
    reply(msg.id, { tools: TOOLS });
  } else if (msg.method === "tools/call" && msg.params?.name === "analyze") {
    const results = (msg.params.arguments?.files ?? []).map((file) => {
      try {
        return analyzeFile(file);
      } catch (err) {
        return { path: file.path, error: String(err.message).slice(0, 200) };
      }
    });
    reply(msg.id, { content: [{ type: "text", text: `${results.length} files` }], structuredContent: { results }, isError: false });
  } else {
    reply(msg.id, undefined, { code: -32601, message: `method not found: ${msg.method}` });
  }
});
