// OpenAPI description of the vuln-notes lab, served at /openapi.json for Veritas recon.
const note = { type: "object", properties: { id: { type: "integer" }, title: { type: "string" }, body: { type: "string" } } };
const noteInput = { type: "object", properties: { title: { type: "string" }, body: { type: "string" } } };
const noteRef = { type: "object", properties: { id: { type: "integer" }, title: { type: "string" } } };
const profile = {
  type: "object",
  properties: { id: { type: "integer" }, email: { type: "string" }, display_name: { type: "string" }, role: { type: "string" } },
};
const json = (schema) => ({ "application/json": { schema } });
const auth = [{ cookieAuth: [] }];
const idParam = [{ name: "id", in: "path", required: true, schema: { type: "integer" } }];
const qParam = [{ name: "q", in: "query", schema: { type: "string" } }];
const nextParam = [{ name: "next", in: "query", schema: { type: "string" } }];
const query = (name) => [{ name, in: "query", schema: { type: "string" } }];
const exportResult = json({ type: "object", properties: { found: { type: "boolean" }, text: { type: "string" } } });
const jobResult = json({ type: "object", properties: { queued: { type: "boolean" }, reason: { type: "string" } } });
const previewResult = json({ type: "object", properties: { preview: { type: "string" }, reason: { type: "string" } } });
const get = (parameters, description, content) => ({ get: { security: auth, parameters, responses: { 200: { description, content } } } });

export const OPENAPI = {
  openapi: "3.0.3",
  info: { title: "vuln-notes (intentionally vulnerable lab)", version: "1.0.0" },
  components: { securitySchemes: { cookieAuth: { type: "apiKey", in: "cookie", name: "sid" } } },
  paths: {
    "/api/login": {
      post: {
        security: [],
        requestBody: {
          content: {
            "application/x-www-form-urlencoded": { schema: { type: "object", properties: { email: { type: "string" }, password: { type: "string" } } } },
          },
        },
        responses: { 200: { description: "signed in" }, 401: { description: "invalid credentials" } },
      },
    },
    "/api/notes": {
      get: { security: auth, responses: { 200: { description: "own notes", content: json({ type: "array", items: note }) } } },
      post: {
        security: auth,
        requestBody: { content: { ...json(noteInput), "application/x-www-form-urlencoded": { schema: noteInput } } },
        responses: { 201: { description: "created" } },
      },
    },
    "/api/notes/{id}": { get: { security: auth, parameters: idParam, responses: { 200: { description: "a note", content: json(note) } } } },
    "/api/v2/notes": { post: { security: auth, requestBody: { content: json(noteInput) }, responses: { 201: { description: "created" } } } },
    "/api/v2/notes/{id}": { get: { security: auth, parameters: idParam, responses: { 200: { description: "own note", content: json(note) } } } },
    "/api/profile": {
      get: { security: auth, responses: { 200: { description: "profile", content: json(profile) } } },
      put: {
        security: auth,
        requestBody: { content: json({ type: "object", properties: { display_name: { type: "string" } } }) },
        responses: { 200: { description: "updated profile", content: json(profile) } },
      },
    },
    "/api/import": {
      post: {
        security: auth,
        requestBody: { content: json({ type: "object", properties: { items: { type: "array", items: noteInput } } }) },
        responses: { 200: { description: "imported" } },
      },
    },
    "/api/search": {
      get: { security: auth, parameters: qParam, responses: { 200: { description: "own notes whose title matches", content: json({ type: "array", items: noteRef }) } } },
    },
    "/api/v2/search": {
      get: { security: auth, parameters: qParam, responses: { 200: { description: "own notes whose title matches", content: json({ type: "array", items: noteRef }) } } },
    },
    "/search": { get: { security: [], parameters: qParam, responses: { 200: { description: "search page", content: { "text/html": {} } } } } },
    "/search2": { get: { security: [], parameters: qParam, responses: { 200: { description: "search page", content: { "text/html": {} } } } } },
    "/api/export": get(query("name"), "an exported note", exportResult),
    "/api/v2/export": get(query("name"), "an exported note", exportResult),
    "/api/thumbnail": get(query("name"), "a thumbnail job", jobResult),
    "/api/v2/thumbnail": get(query("name"), "a thumbnail job", jobResult),
    "/api/preview": get(query("url"), "a link preview", previewResult),
    "/api/v2/preview": get(query("feed"), "a feed preview", previewResult),
    "/go": { get: { security: [], parameters: nextParam, responses: { 302: { description: "redirect to next" } } } },
    "/go2": { get: { security: [], parameters: nextParam, responses: { 302: { description: "redirect to a named destination" } } } },
  },
};
