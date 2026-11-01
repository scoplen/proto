// SPDX-License-Identifier: Apache-2.0
// Independent D-137 deterministic CBOR writer; no Rust codec or consumer is invoked.
import { readFile, writeFile } from "node:fs/promises";
const root = new URL("../", import.meta.url);
const vectors = [], outputs = [];
const id = n => Buffer.from(`000000000000700080000000000000${n.toString(16).padStart(2, "0")}`, "hex");
const max = (1n << 64n) - 1n;
function head(major, value) {
  const n = BigInt(value);
  if (n < 24n) return Buffer.from([major << 5 | Number(n)]);
  const size = n <= 255n ? 1 : n <= 65535n ? 2 : n <= 4294967295n ? 4 : 8;
  const out = Buffer.alloc(size + 1); out[0] = major << 5 | ({ 1: 24, 2: 25, 4: 26, 8: 27 })[size];
  if (size === 8) out.writeBigUInt64BE(n, 1); else out.writeUIntBE(Number(n), 1, size);
  return out;
}
function cbor(value) {
  if (value === null) return Buffer.from([0xf6]);
  if (Buffer.isBuffer(value)) return Buffer.concat([head(2, value.length), value]);
  if (typeof value === "string") { const bytes = Buffer.from(value); return Buffer.concat([head(3, bytes.length), bytes]); }
  if (typeof value === "boolean") return Buffer.from([value ? 0xf5 : 0xf4]);
  if (typeof value === "number" || typeof value === "bigint") return head(0, value);
  if (Array.isArray(value)) return Buffer.concat([head(4, value.length), ...value.map(cbor)]);
  const entries = value instanceof Map ? [...value] : Object.entries(value);
  const pairs = entries.map(([key, item]) => [cbor(key), cbor(item)]).sort(([a], [b]) => Buffer.compare(a, b));
  return Buffer.concat([head(5, pairs.length), ...pairs.flat()]);
}
function add(name, kind, bytes, canonical = bytes) {
  const input = kind === "query" ? bytes : bytes.toString("hex");
  const expected = canonical === null ? "rejected" : kind === "query" ? canonical : canonical.toString("hex");
  const vector = { id: `organization-view-${name}-v1`, kind: `sync.organization.${kind}`, input, expected };
  vectors.push(vector);
  const selector = { problem: 16, query: 17, view: 18, ack_request: 19, ack_response: 20 }[kind];
  if (selector !== undefined) outputs.push([`fuzz/corpus/sync_data/seed-${vector.id}`, Buffer.concat([Buffer.from([selector]), Buffer.from(bytes)])]);
  if (kind === "session") outputs.push([`fuzz/corpus/sync_control/seed-${vector.id}`, Buffer.concat([Buffer.from([1]), bytes])]);
  if (kind === "notification") outputs.push([`fuzz/corpus/sync_notification/seed-${vector.id}`, bytes]);
}
const objectFields = new Map([[1, ["Example", 1, id(4)]], [2, ["host.example", 1, id(4)]]]);
const objectMap = new Map([[1, id(3)], [2, 1], [3, 1], [4, objectFields]]);
const object = cbor(objectMap);
const change = new Map([[1, id(3)], [2, 5], [3, object], [4, false], [5, null]]);
const page = { organization: id(1), vault: id(2), view_revision: 7, objects: [change], next_cursor: 8, more: false };
const changed = (key, value) => new Map([...change].map(([k, v]) => [k, k === key ? value : v]));
for (const [name, value] of [
  ["page", page], ["empty", { ...page, objects: [] }], ["continuation", { ...page, next_cursor: 5, more: true }],
  ["maximum", { ...page, view_revision: max, next_cursor: max }],
]) add(name, "view", cbor(value));
add("page-extension", "view", cbor({ ...page, future: { accepted: true } }), cbor(page));
for (const [name, value] of [
  ["zero-revision", { ...page, view_revision: 0 }], ["nil-owner", { ...page, organization: Buffer.alloc(16) }],
  ["nil-vault", { ...page, vault: Buffer.alloc(16) }], ["empty-more", { ...page, objects: [], more: true }],
  ["cursor-backwards", { ...page, next_cursor: 4 }], ["more-gap", { ...page, more: true }],
  ["duplicate-object", { ...page, objects: [change, change] }],
  ["tombstone", { ...page, objects: [changed(4, true)] }], ["signed", { ...page, objects: [changed(5, id(4))] }],
  ["invalid-object", { ...page, objects: [changed(3, cbor(null))] }], ["object-id", { ...page, objects: [changed(1, id(4))] }],
  ["deleted-object", { ...page, objects: [changed(3, cbor(new Map([...objectMap, [5, [2, id(4)]]])))] }],
  ["missing-objects", { ...page, objects: null }],
]) add(name, "view", cbor(value), null);
add("query", "query", "revision=7&after=0&limit=10");
add("query-order", "query", "limit=10&after=0&revision=7", "revision=7&after=0&limit=10");
add("query-maximum", "query", `revision=${max}&after=${max}&limit=1000`);
for (const [name, value] of [
  ["zero", "revision=0&after=0&limit=10"], ["leading-zero", "revision=07&after=0&limit=10"],
  ["duplicate", "revision=7&after=0&limit=10&revision=7"], ["unknown", "revision=7&after=0&limit=10&x=1"],
  ["missing", "after=0&limit=10"], ["limit", "revision=7&after=0&limit=1001"],
  ["overflow", `revision=${max + 1n}&after=0&limit=10`], ["encoded", "revision=%37&after=0&limit=10"],
]) add(`query-${name}`, "query", value, null);
for (const kind of ["ack_request", "ack_response"]) {
  const ack = { cursor: 8, view_revision: 7 };
  add(kind, kind, cbor(ack));
  add(`${kind}-maximum`, kind, cbor({ cursor: max, view_revision: max }));
  add(`${kind}-zero`, kind, cbor({ cursor: 0, view_revision: 0 }), null);
  add(`${kind}-missing`, kind, cbor({ cursor: 0 }), null);
  add(`${kind}-extension`, kind, cbor({ ...ack, future: true }), kind === "ack_response" ? cbor(ack) : null);
}
const base = JSON.parse((JSON.parse(await readFile(new URL("vectors/sync-session.json", root), "utf8"))).vectors.find(v => v.kind === "sync.session.response").input);
const descriptor = { id: id(2), kind: "organization", seq: 0, key_epoch: 1, rotation_pending: false, organization: id(1), view_revision: 7 };
const session = vault => ({ ...base, vaults: [vault] });
add("session", "session", cbor(session(descriptor)));
add("session-maximum", "session", cbor(session({ ...descriptor, view_revision: max })));
for (const key of ["organization", "view_revision"]) {
  const missing = { ...descriptor }; delete missing[key];
  add(`session-missing-${key}`, "session", cbor(session(missing)), null);
}
add("session-zero", "session", cbor(session({ ...descriptor, view_revision: 0 })), null);
const membershipHint = { memberships_changed: true };
const viewHint = { organization_view_changed: true, organization: id(1), vault: id(2), view_revision: 7 };
for (const [name, value] of [["memberships", membershipHint], ["view-hint", viewHint]]) {
  add(name, "notification", cbor(value));
  add(`${name}-extension`, "notification", cbor({ ...value, future: true }), cbor(value));
  for (const key of ["seq", "rotation_pending", "device_revoked", "htm", "authenticated"])
    add(`${name}-${key}`, "notification", cbor({ ...value, [key]: null }), null);
}
for (const key of ["organization", "vault", "view_revision", "organization_view_changed"])
  add(`memberships-${key}`, "notification", cbor({ ...membershipHint, [key]: null }), null);
add("hint-zero", "notification", cbor({ ...viewHint, view_revision: 0 }), null);
add("memberships-false", "notification", cbor({ memberships_changed: false }), null);
add("revision-changed", "problem", cbor({
  type: "about:blank", title: "Team view changed", status: 409,
  detail: "Refresh the team descriptor and restart the complete view.", instance: "view-1",
  code: "sync.view_changed", changed: false, retryable: true,
}));
outputs.unshift(["vectors/organization-view.json", JSON.stringify({ format: "scoplen-test-vectors", version: 1, vectors }, null, 2) + "\n"]);
if (new Set(vectors.map(v => v.id)).size !== vectors.length) throw new Error("duplicate Organization view vector id");
for (const [path, expected] of outputs) {
  const url = new URL(path, root);
  if (process.argv.includes("--check")) {
    const actual = await readFile(url);
    const normalized = path.endsWith(".json") ? Buffer.from(actual.toString("utf8").replaceAll("\r\n", "\n")) : actual;
    if (!normalized.equals(Buffer.from(expected))) throw new Error(`D-137 output stale: ${path}`);
  } else await writeFile(url, expected);
}
console.log(`validated ${vectors.length} D-137 Organization view vectors and ${outputs.length - 1} parser seeds`);
