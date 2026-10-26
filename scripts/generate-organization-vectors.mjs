// SPDX-License-Identifier: Apache-2.0
// Independent D-130 JSON examples and parser-bound recipes; no Rust codec is called.
import { readFile, writeFile } from "node:fs/promises";
const root = new URL("../", import.meta.url);
const vectors = [];
const id = n => `019bdad6-b800-7000-8000-${String(n).padStart(12, "0")}`;
const request = { data: { name: "Operations" } };
const resource = { id: id(1), etag: '"1"', created_at: "2026-10-26T00:00:00Z", updated_at: "2026-10-26T00:00:00Z", data: { name: "Operations", membership: { id: id(2), account_id: id(3), roles: ["owner"] } } };
const canonical = JSON.stringify(resource);
const add = (id, kind, input, expected = "rejected") => vectors.push({ id: `organization-${id}-v1`, kind: `organization.${kind}`, input, expected });
add("create", "create", JSON.stringify(request), JSON.stringify(request));
add("create-whitespace", "create", ' { "data" : { "name" : "Operations" } }', JSON.stringify(request));
add("create-unicode", "create", '{"data":{"name":"团队"}}', '{"data":{"name":"团队"}}');
for (const [suffix, input] of [
  ["unknown", '{"data":{"name":"Operations","owner":"other"}}'],
  ["account", '{"data":{"name":"Operations"},"account_id":"other"}'],
  ["duplicate", '{"data":{"name":"Operations","name":"Other"}}'],
  ["escaped-duplicate", '{"data":{"name":"Operations","n\\u0061me":"Other"}}'],
  ["empty", '{"data":{"name":""}}'], ["edge-space", '{"data":{"name":" Operations"}}'],
  ["control", '{"data":{"name":"Ops\\n"}}'], ["missing", '{"data":{}}'],
  ["null", 'null'], ["trailing", '{}{}'], ["bom", '\ufeff{"data":{"name":"Operations"}}'],
]) add(`create-${suffix}`, "create.reject", input);
add("resource", "resource", canonical, canonical);
const unordered = structuredClone(resource); unordered.data.membership.roles = ["security_auditor", "future_reader", "administrator"];
const ordered = structuredClone(unordered); ordered.data.membership.roles.sort();
add("resource-roles-order", "resource", JSON.stringify(unordered), JSON.stringify(ordered));
const extended = structuredClone(resource); extended.extra = { metadata: true }; extended.data.membership.extension = [];
add("resource-extensions", "resource", JSON.stringify(extended), canonical);
for (const [suffix, mutate] of [
  ["account", r => { r.data.membership.account_id = "019BDAD6-B800-7000-8000-000000000003"; }],
  ["roles-empty", r => { r.data.membership.roles = []; }],
  ["roles-duplicate", r => { r.data.membership.roles = ["owner", "owner"]; }],
  ["roles-invalid", r => { r.data.membership.roles = ["Owner"]; }],
  ["missing-member", r => { delete r.data.membership; }],
  ["weak-etag", r => { r.etag = 'W/"1"'; }],
  ["calendar", r => { r.created_at = "2026-02-30T00:00:00Z"; }],
]) { const r = structuredClone(resource); mutate(r); add(`resource-${suffix}`, "resource.reject", JSON.stringify(r)); }
add("resource-nested-duplicate", "resource.reject", canonical.slice(0, -1) + ',"extra":{"x":1,"x":2}}');
const page = { items: [resource], next_cursor: null };
add("page", "page", JSON.stringify(page), JSON.stringify(page));
add("empty-page", "page", '{"items":[],"next_cursor":null}', '{"items":[],"next_cursor":null}');
add("page-next", "page", JSON.stringify({ ...page, next_cursor: id(1) }), JSON.stringify({ ...page, next_cursor: id(1) }));
for (const [suffix, input] of [
  ["duplicate", JSON.stringify({ items: [resource, resource], next_cursor: null })],
  ["next-mismatch", JSON.stringify({ ...page, next_cursor: id(2) })],
  ["empty-next", JSON.stringify({ items: [], next_cursor: id(1) })],
  ["missing-next", '{"items":[]}'],
]) add(`page-${suffix}`, "page.reject", input);
for (const [suffix, parameters, expected] of [
  ["default", [], { limit: 50, cursor: null }], ["max", [["limit", "500"]], { limit: 500, cursor: null }],
  ["cursor", [["cursor", id(1)], ["limit", "1"]], { limit: 1, cursor: id(1) }],
  ["zero", [["limit", "0"]], null], ["over", [["limit", "501"]], null],
  ["repeat", [["limit", "1"], ["limit", "2"]], null], ["unknown", [["filter", "all"]], null],
]) add(`query-${suffix}`, "query", JSON.stringify(parameters), expected ? JSON.stringify(expected) : "rejected");
for (const [kind, base, bound] of [["create", JSON.stringify(request), 1024], ["resource", canonical, 4096], ["page", '{"items":[],"next_cursor":null}', 2097152]]) {
  for (const extra of [0, 1]) add(`${kind}-bound-${extra}`, "bound", JSON.stringify({ kind, base, bytes: bound + extra }), extra ? "rejected" : "accepted");
}
const outputs = [["vectors/organizations.json", JSON.stringify({ format: "scoplen-test-vectors", version: 1, vectors }, null, 2) + "\n"]];
if (new Set(vectors.map(vector => vector.id)).size !== vectors.length) throw new Error("duplicate D-130 vector id");
for (const vector of vectors.filter(v => ["create", "resource", "page", "create.reject", "resource.reject", "page.reject"].includes(v.kind.slice("organization.".length)))) outputs.push([`fuzz/corpus/api_json/seed-${vector.id}`, vector.input]);
for (const [kind, base, bound] of [["create", JSON.stringify(request), 1024], ["resource", canonical, 4096]]) {
  for (const extra of [0, 1]) outputs.push([`fuzz/corpus/api_json/seed-organization-${kind}-bound-${extra}`, " ".repeat(bound + extra - Buffer.byteLength(base)) + base]);
}
for (const [path, expected] of outputs) {
  const url = new URL(path, root);
  if (process.argv.includes("--check")) {
    const actual = await readFile(url, "utf8");
    if ((path.endsWith(".json") ? actual.replaceAll("\r\n", "\n") : actual) !== expected) throw new Error(`D-130 output stale: ${path}`);
  } else await writeFile(url, expected);
}
console.log(`validated ${vectors.length} D-130 vectors and ${outputs.length - 1} parser seeds`);
