// SPDX-License-Identifier: Apache-2.0
// Independent D-137 named-field JSON and deterministic K-1 producer; no Rust code is called.
import { createHash, createPrivateKey, createPublicKey } from "node:crypto";
import { readFile, readdir, unlink, writeFile } from "node:fs/promises";

const root = new URL("../", import.meta.url);
const id = n => `019bdad6-b800-7000-8000-${String(n).padStart(12, "0")}`;
const time = "2026-11-01T00:00:00Z";
const clock = 65536000n;
const writer = id(90);
const attribution = { accepted_at: "1800000000000", accepted_by_device: writer, accepted_by_account: id(91) };
const sshString = bytes => { bytes = Buffer.from(bytes); const length = Buffer.alloc(4); length.writeUInt32BE(bytes.length); return Buffer.concat([length, bytes]); };
const publicBytes = createPublicKey(createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.alloc(32, 7)]), format: "der", type: "pkcs8" })).export({ format: "der", type: "spki" }).subarray(-32);
const keyBlob = Buffer.concat([sshString("ssh-ed25519"), sshString(publicBytes)]);
const key = "ssh-ed25519 " + keyBlob.toString("base64");
const fingerprint = "SHA256:" + createHash("sha256").update(keyBlob).digest("base64").replace(/=+$/, "");
const definitions = {
  hosts: [[1, "name", "text"], [2, "address", "text"], [3, "port", "uint"], [4, "tags", "textmap"], [5, "groups", "uuidset"], [6, "favorite", "bool"], [7, "notes", "text"], [8, "default_profile", "uuid"], [9, "ssh_options", "textmap"], [10, "mosh", "textmap"]],
  "access-profiles": [[1, "host", "uuid"], [2, "name", "text"], [3, "username", "text"], [5, "route", "route"], [6, "terminal_profile", "text"], [7, "startup_command", "text"], [9, "agent_forwarding", "bool"]],
  routes: [[1, "name", "text"], [2, "kind", "uint"], [3, "hops", "uuids"], [4, "proxy", "text"], [6, "command", "text"], [7, "gateway_network", "uuid"], [8, "proxy_username", "text"]],
  "host-groups": [[1, "name", "text"], [2, "parent", "uuid"], [3, "color", "text"], [4, "defaults", "textmap"]],
  "trust-records": [[1, "host", "uuid"], [2, "pattern", "text"], [3, "key", "text"], [4, "fingerprint", "text"], [5, "provenance", "uint"], [6, "accepted_at", "decimal"], [7, "accepted_by_device", "uuid"], [8, "accepted_by_account", "uuid"], [9, "revoked", "bool"], [10, "ca", "bool"]],
  snippets: [[1, "name", "text"], [2, "template", "text"], [3, "variables", "variables"], [4, "tags", "textset"], [5, "folder", "text"]],
  "gateway-networks": [[1, "name", "text"], [2, "description", "text"]],
};
const types = { hosts: 1, "access-profiles": 2, routes: 4, "host-groups": 5, "trust-records": 6, snippets: 7, "gateway-networks": 11 };
const examples = {
  hosts: { name: "Bastion", address: "host.example.test", port: 22, tags: { zone: "west", env: "prod" }, groups: { [id(30)]: true }, favorite: false, notes: " Café ", default_profile: id(20), ssh_options: { Compression: "yes" }, mosh: { predict: "adaptive" } },
  "access-profiles": { host: id(10), name: "Operations", username: "deploy", route: 0, terminal_profile: "Default", startup_command: "pwd", agent_forwarding: false },
  routes: { name: "Jump", kind: 1, hops: [id(20), id(21)] },
  "host-groups": { name: "Production", parent: id(31), color: "#444444", defaults: { username: "deploy", route: id(40) } },
  "trust-records": { host: id(10), pattern: "*.example.test", key, fingerprint, provenance: 4, revoked: false, ca: true },
  snippets: { name: "Inspect", template: "echo {{text}} {{count}} {{mode}} {{secret}}", variables: { text: { kind: 1, default: "ok" }, count: { kind: 2, default: "-9223372036854775808" }, mode: { kind: 3, default: "safe", choices: ["safe", "fast"] }, secret: { kind: 4 } }, tags: { ops: true }, folder: "Operations" },
  "gateway-networks": { name: "Primary", description: "Managed network" },
};
const minimal = { hosts: { name: "", address: "" }, "access-profiles": { host: id(10), username: "" }, routes: { name: "", kind: 1, hops: [] }, "host-groups": { name: "" }, "trust-records": { host: id(10) }, snippets: { name: "", template: "" }, "gateway-networks": {} };
const compare = (a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b));
const ordered = value => Array.isArray(value) ? value.map(ordered) : value && typeof value === "object" ? Object.fromEntries(Object.keys(value).sort(compare).map(k => [k, ordered(value[k])])) : value;
const normalized = (type, fields) => Object.fromEntries(Object.entries(ordered(fields)).filter(([name, value]) => !definitions[type].some(([, key, shape]) => key === name && ["textmap", "uuidset", "textset", "variables"].includes(shape) && Object.keys(value).length === 0)));
const responseFields = (type, fields) => ordered(type === "trust-records" ? { ...fields, ...attribution } : fields);
const create = (type, fields = examples[type], objectId = id(10)) => ({ id: objectId, data: { fields: normalized(type, fields) } });
const replace = (type, fields = examples[type]) => ({ data: { fields: normalized(type, fields) } });
const resource = (type, fields = examples[type], objectId = id(10)) => ({ id: objectId, etag: '"inventory-current"', created_at: time, updated_at: time, data: { fields: normalized(type, responseFields(type, fields)), schema: 1 } });
const json = JSON.stringify;
const vectors = [];
const add = (name, kind, type, input, expected = "rejected") => vectors.push({ id: `inventory-${type.replace(/[^a-zA-Z0-9-]/g, "_")}-${name}-v1`, kind: `inventory.${kind}`, input: json({ type, json: typeof input === "string" ? input : json(input) }), expected });

// A separate minimal deterministic encoder for known-answer K-1 bytes.
function head(major, value) {
  value = BigInt(value);
  if (value < 24n) return Buffer.from([major * 32 + Number(value)]);
  const widths = [[255n, 1, 24], [65535n, 2, 25], [4294967295n, 4, 26], [18446744073709551615n, 8, 27]];
  for (const [max, width, suffix] of widths) if (value <= max) {
    const out = Buffer.alloc(1 + width); out[0] = major * 32 + suffix;
    for (let i = width; i > 0; i--) { out[i] = Number(value & 255n); value >>= 8n; }
    return out;
  }
  throw new Error("integer outside deterministic CBOR");
}
function cbor(value) {
  if (typeof value === "boolean") return Buffer.from([value ? 245 : 244]);
  if (typeof value === "number" || typeof value === "bigint") { value = BigInt(value); return value >= 0n ? head(0, value) : head(1, -1n - value); }
  if (typeof value === "string") { const bytes = Buffer.from(value); if (value.normalize("NFC") !== value) throw new Error("non-NFC fixture"); return Buffer.concat([head(3, bytes.length), bytes]); }
  if (Buffer.isBuffer(value)) return Buffer.concat([head(2, value.length), value]);
  if (Array.isArray(value)) return Buffer.concat([head(4, value.length), ...value.map(cbor)]);
  if (value instanceof Map) {
    const entries = [...value].map(([k, v]) => [cbor(k), cbor(v)]).sort(([a], [b]) => Buffer.compare(a, b));
    return Buffer.concat([head(5, entries.length), ...entries.flat()]);
  }
  throw new Error("unsupported known-answer value");
}
const uuidBytes = value => Buffer.from(value.replaceAll("-", ""), "hex");
function modelBytes(type, fields, objectId = id(10)) {
  const values = new Map();
  for (const [number, name, shape] of definitions[type]) {
    if (!(name in fields)) continue;
    const value = fields[name];
    const put = (path, val) => values.set(path, [val, clock, uuidBytes(writer)]);
    if (["textmap", "uuidset", "textset", "variables"].includes(shape)) {
      for (const [key, val] of Object.entries(value)) {
        let item = val;
        if (shape === "variables") {
          item = new Map([[1, val.kind]]);
          if ("default" in val) item.set(2, val.kind === 2 ? BigInt(val.default) : val.default);
          if ("choices" in val) item.set(3, val.choices);
        }
        put([number, shape === "uuidset" ? uuidBytes(key) : key], item);
      }
    } else put(number, shape === "uuid" || (shape === "route" && value !== 0) ? uuidBytes(value) : shape === "uuids" ? value.map(uuidBytes) : shape === "decimal" ? BigInt(value) : value);
  }
  return cbor(new Map([[1, uuidBytes(objectId)], [2, types[type]], [3, 1], [4, values]])).toString("hex");
}

for (const type of Object.keys(examples)) {
  for (const [kind, value] of [["create", create(type)], ["replace", replace(type)], ["resource", resource(type)], ["page", { items: [resource(type)], next_cursor: null }]]) {
    add(kind, kind, type, value, json(value));
    add(`${kind}-whitespace`, kind, type, `\t${json(value)}`, json(value));
    add(`${kind}-duplicate`, kind, type, json(value).slice(0, -1) + ',"extra":{"x":1,"x":2}}');
    add(`${kind}-bom`, kind, type, "\ufeff" + json(value));
    const missing = structuredClone(value); delete missing[Object.keys(missing)[0]];
    add(`${kind}-missing`, kind, type, missing);
    if (["create", "replace"].includes(kind)) add(`${kind}-extension`, kind, type, { ...value, extra: 1 });
    else add(`${kind}-extension`, kind, type, { ...value, extra: { opaque: true } }, json(value));
  }
  add("fields", "fields", type, examples[type], json(normalized(type, examples[type])));
  add("minimal-fields", "fields", type, minimal[type], json(normalized(type, minimal[type])));
  add("unknown-field", "fields", type, { ...examples[type], unknown: true });
  add("null-field", "fields", type, { ...examples[type], [Object.keys(examples[type])[0] ?? "name"]: null });
  add("non-nfc", "fields", type, { ...examples[type], [type === "trust-records" ? "pattern" : "name"]: "e\u0301" });
  const required = { hosts: ["name", "address"], "access-profiles": ["host", "username"], routes: ["name", "kind", "hops"], "host-groups": ["name"], "trust-records": ["host", "pattern"], snippets: ["name", "template"], "gateway-networks": [] };
  for (const name of required[type]) {
    const missing = structuredClone(examples[type]); delete missing[name];
    if (type === "trust-records") { delete missing.host; delete missing.pattern; }
    add(`required-${name}`, "fields", type, missing);
  }
  for (const [, name, shape] of definitions[type].filter(([, name]) => !(name in attribution))) {
    add(`null-${name}`, "fields", type, { ...examples[type], [name]: null });
    add(`wrong-shape-${name}`, "fields", type, { ...examples[type], [name]: shape === "bool" ? "true" : false });
  }
  const modelInput = { type, fields: responseFields(type, examples[type]), id: id(10), clock: String(clock), writer };
  vectors.push({ id: `inventory-${type}-k1-v1`, kind: "inventory.model", input: json(modelInput), expected: modelBytes(type, modelInput.fields) });
  for (const kind of ["create", "resource", "page"]) {
    const value = kind === "create" ? create(type) : kind === "resource" ? resource(type) : { items: [resource(type)], next_cursor: null };
    const bound = kind === "page" ? 8388608 : 2097152;
    for (const extra of [0, 1]) vectors.push({ id: `inventory-${type}-${kind}-bound-${extra}-v1`, kind: "inventory.bound", input: json({ type, kind, base: json(value), bytes: bound + extra }), expected: extra ? "rejected" : "accepted" });
  }
  const badSchema = resource(type); badSchema.data.schema = 2;
  add("future-schema", "resource", type, badSchema);
  for (const schema of ['"1"', "1.0", "1e0", "0"]) add(`schema-alias-${schema.replaceAll('"', 's')}`, "resource", type, json(resource(type)).replace('"schema":1', `"schema":${schema}`));
  const readExtension = resource(type); readExtension.data.extension = true;
  add("data-extension", "resource", type, readExtension, json(resource(type)));
  const unknownModel = resource(type); unknownModel.data.fields.unknown = "future";
  add("unknown-model-field", "resource", type, unknownModel);
}
function fieldCases(type, cases) {
  for (const [name, patch] of cases) add(name, "fields", type, { ...examples[type], ...patch });
}
fieldCases("hosts", [["zero-port", { port: 0 }], ["overflow-port", { port: 65536 }], ["false-group", { groups: { [id(30)]: false } }], ["uuid-case", { default_profile: id(20).toUpperCase() }], ["null-map-entry", { tags: { env: null } }], ["map-value", { ssh_options: { Compression: true } }], ["map-key-nfc", { tags: { "e\u0301": "prod" } }]]);
for (const port of ["22.0", "22e0", '"22"']) add(`port-alias-${port.replaceAll('"', "s")}`, "fields", "hosts", `{"name":"host","address":"example.test","port":${port}}`);
for (const [name, type, patch] of [["credential", "access-profiles", { credential: id(22) }], ["forwards", "access-profiles", { forwards: {} }], ["route-string-zero", "access-profiles", { route: "0" }], ["default-credential", "host-groups", { defaults: { credential: id(22) } }], ["proxy-credential", "routes", { name: "Proxy", kind: 2, proxy: "proxy.example.test:1080", proxy_credential: id(22), proxy_username: "proxy" }]]) fieldCases(type, [[name, patch]]);
for (const route of [{ name: "SOCKS", kind: 2, proxy: "proxy.example.test:1080" }, { name: "CONNECT", kind: 3, proxy: "proxy.example.test:3128" }, { name: "Command", kind: 4, command: "ssh -W %h:%p relay" }, { name: "Managed", kind: 5, gateway_network: id(70) }]) add(`route-kind-${route.kind}`, "fields", "routes", route, json(ordered(route)));
fieldCases("routes", [["route-unknown-kind", { kind: 6 }], ["route-proxy-without-address", { kind: 2 }], ["route-mixed-shapes", { kind: 4, command: "ssh" }], ["route-null-hop", { hops: [null] }]]);
fieldCases("host-groups", [["default-route-invalid", { defaults: { route: "unknown" } }], ["default-route-uppercase", { defaults: { route: id(40).toUpperCase() } }]]);
add("default-direct-route", "fields", "host-groups", { name: "Group", defaults: { route: "0" } }, json(ordered({ name: "Group", defaults: { route: "0" } })));
for (const name of Object.keys(attribution)) fieldCases("trust-records", [[`readonly-${name}`, { [name]: attribution[name] }]]);
fieldCases("trust-records", [["wrong-fingerprint", { fingerprint: fingerprint + "x" }], ["malformed-key", { key: "ssh-ed25519 invalid" }], ["unknown-provenance", { provenance: 5 }]]);
for (const text of ["01", "-1", "+1", "18446744073709551616", "1.0"]) { const value = resource("trust-records"); value.data.fields.accepted_at = text; add(`timestamp-${text.replaceAll("+", "plus")}`, "resource", "trust-records", value); }
for (const text of ["0", "18446744073709551615"]) { const value = resource("trust-records"); value.data.fields.accepted_at = text; add(`timestamp-valid-${text}`, "resource", "trust-records", value, json(value)); }
for (const [index, spec] of [{ kind: 1, default: null }, { kind: 2, default: 1 }, { kind: 2, default: "01" }, { kind: 2, default: "-0" }, { kind: 2, default: "9223372036854775808" }, { kind: 3, choices: [] }, { kind: 3, choices: ["a", "a"] }, { kind: 3, choices: ["a"], default: "b" }, { kind: 4, default: "saved" }, { kind: 1, choices: ["a"] }, { kind: 5 }, { kind: 1, extra: true }].entries()) fieldCases("snippets", [[`variable-invalid-${index}`, { variables: { input: spec } }]]);
for (const value of ["-9223372036854775808", "0", "9223372036854775807"]) { const fields = { name: "Count", template: "{{n}}", variables: { n: { kind: 2, default: value } } }; add(`integer-${value}`, "fields", "snippets", fields, json(ordered(fields))); }
for (const type of ["hosts", "host-groups", "snippets"]) {
  const empty = type === "hosts" ? { tags: {}, groups: {}, ssh_options: {}, mosh: {} } : type === "host-groups" ? { defaults: {} } : { variables: {}, tags: {} };
  add("empty-maps", "fields", type, { ...minimal[type], ...empty }, json(normalized(type, minimal[type])));
}
for (const type of ["credentials", "forwards", "workspaces", "preferences", "Hosts", "hosts/"]) add("forbidden-type", "fields", type, {});
for (const [name, page] of [["empty-page", { items: [], next_cursor: null }], ["continuation-page", { items: [resource("hosts")], next_cursor: id(10) }]]) add(name, "page", "hosts", page, json(page));
for (const [name, page] of [["duplicate-page", { items: [resource("hosts"), resource("hosts")], next_cursor: null }], ["reverse-page", { items: [resource("hosts", examples.hosts, id(11)), resource("hosts")], next_cursor: null }], ["empty-next", { items: [], next_cursor: id(10) }], ["wrong-next", { items: [resource("hosts")], next_cursor: id(11) }]]) add(name, "page", "hosts", page);
if (new Set(vectors.map(v => v.id)).size !== vectors.length) throw new Error("duplicate inventory vector id");
const outputs = [["vectors/organization-inventory.json", json({ format: "scoplen-test-vectors", version: 1, vectors }, null, 2) + "\n"]];
for (const vector of vectors.filter(v => !["inventory.bound", "inventory.model"].includes(v.kind))) outputs.push([`fuzz/corpus/api_json/seed-${vector.id}`, JSON.parse(vector.input).json]);
const expectedSeeds = new Set(outputs.slice(1).map(([path]) => path.split("/").at(-1)));
const corpus = new URL("fuzz/corpus/api_json/", root);
for (const entry of await readdir(corpus, { withFileTypes: true })) {
  if (!entry.isFile() || !entry.name.startsWith("seed-inventory-") || expectedSeeds.has(entry.name)) continue;
  if (process.argv.includes("--check")) throw new Error(`D-137 inventory output stale: ${entry.name}`);
  await unlink(new URL(entry.name, corpus));
}
for (const [path, expected] of outputs) {
  const url = new URL(path, root);
  if (process.argv.includes("--check")) {
    const actual = await readFile(url, "utf8");
    if ((path.endsWith(".json") ? actual.replaceAll("\r\n", "\n") : actual) !== expected) throw new Error(`D-137 inventory output stale: ${path}`);
  } else await writeFile(url, expected);
}
console.log(`validated ${vectors.length} D-137 inventory vectors and ${outputs.length - 1} parser seeds`);
