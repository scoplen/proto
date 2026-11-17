// SPDX-License-Identifier: Apache-2.0
// Independent D-147 examples; no Rust implementation is called.
import { readFile, writeFile } from "node:fs/promises";

const root = new URL("../", import.meta.url);
const id = n => `019bdad6-b800-7000-8000-${String(n).padStart(12, "0")}`;
const json = JSON.stringify;
const time = "2026-11-01T00:00:00Z";
const fields = { membership: id(2), host: id(3), remote_user: "deploy", valid_from: "1970-01-01T00:00:00Z", valid_until: "9999-12-31T23:59:59Z" };
const resource = { id: id(4), etag: '"current"', created_at: time, updated_at: time, data: fields };
const examples = { create: { id: id(4), data: fields }, replace: { data: fields }, resource, page: { items: [resource], next_cursor: null } };
const vectors = [];
const add = (name, kind, input, expected = "rejected") => vectors.push({ id: `grant-${name}-v1`, kind: `grant.${kind}`, input: typeof input === "string" ? input : json(input), expected });
for (const [kind, value] of Object.entries(examples)) {
  add(kind, kind, value, json(value));
  add(`${kind}-whitespace`, kind, `\t ${json(value)}`, json(value));
  add(`${kind}-missing`, kind, {});
  add(`${kind}-duplicate`, kind, json(value).slice(0, -1) + ',"future":{"x":1,"x":2}}');
  add(`${kind}-extension`, kind, { ...value, future: true }, ["resource", "page"].includes(kind) ? json(value) : "rejected");
}
for (const kind of ["create", "replace", "resource"]) {
  const value = examples[kind];
  for (const [name, replacement, accepted] of [
    ["nonexpiring", { valid_until: null }, true],
    ["future", { valid_from: "9999-12-31T23:59:58Z" }, true],
    ["expired", { valid_until: "1970-01-01T00:00:01Z" }, true],
    ["exact-user", { remote_user: " e\u0301 " }, true],
    ["max-user", { remote_user: "é".repeat(127) + "x" }, true],
    ["empty-user", { remote_user: "" }, false],
    ["excess-user", { remote_user: "é".repeat(128) }, false],
    ["control-user", { remote_user: "bad\u0085user" }, false],
    ["bad-member", { membership: id(2).toUpperCase() }, false],
    ["bad-host", { host: "00000000-0000-0000-0000-000000000000" }, false],
    ["equal-end", { valid_until: fields.valid_from }, false],
    ["fraction", { valid_from: "1970-01-01T00:00:00.000Z" }, false],
    ["offset", { valid_from: "1970-01-01T00:00:00+00:00" }, false],
    ["pre-epoch", { valid_from: "1969-12-31T23:59:59Z" }, false],
    ["leap-second", { valid_from: "2016-12-31T23:59:60Z" }, false],
    ["bad-leap-day", { valid_from: "2100-02-29T00:00:00Z" }, false],
    ["leap-day", { valid_from: "2000-02-29T00:00:00Z" }, true],
    ["null-start", { valid_from: null }, false],
  ]) {
    const changed = { ...value, data: { ...fields, ...replacement } };
    add(`${kind}-${name}`, kind, changed, accepted ? json(changed) : "rejected");
  }
  for (const field of Object.keys(fields)) {
    const changed = structuredClone(value); delete changed.data[field];
    add(`${kind}-missing-${field}`, kind, changed);
  }
  const extended = { ...value, data: { ...fields, future: "bounded" } };
  add(`${kind}-nested-extension`, kind, extended, kind === "resource" ? json(value) : "rejected");
  const duplicate = json(value).replace('"remote_user":"deploy"', '"remote_user":"deploy","remote_user":"other"');
  add(`${kind}-duplicate-user`, kind, duplicate);
}
add("page-empty", "page", { items: [], next_cursor: null }, '{"items":[],"next_cursor":null}');
add("page-continuation", "page", { items: [resource], next_cursor: id(4) }, json({ items: [resource], next_cursor: id(4) }));
add("page-missing-cursor", "page", { items: [] });
add("page-wrong-cursor", "page", { items: [resource], next_cursor: id(99) });
add("page-duplicate-items", "page", { items: [resource, resource], next_cursor: null });
add("page-reversed-items", "page", { items: [{ ...resource, id: id(5) }, resource], next_cursor: null });
add("resource-weak-etag", "resource", { ...resource, etag: 'W/"current"' });
for (const [name, timestamp, expected] of [
  ["epoch", fields.valid_from, "0"], ["2038", "2038-01-19T03:14:08Z", "2147483648"],
  ["leap", "2000-02-29T00:00:00Z", "951782400"], ["maximum", fields.valid_until, "253402300799"],
  ["fraction", "2000-02-29T00:00:00.001Z", "rejected"], ["century", "2100-02-29T00:00:00Z", "rejected"],
]) add(`timestamp-${name}`, "timestamp", timestamp, expected);

if (new Set(vectors.map(value => value.id)).size !== vectors.length) throw new Error("duplicate vector id");
const outputs = [["vectors/grant.json", json({ format: "scoplen-test-vectors", version: 1, vectors }, null, 2) + "\n"]];
for (const vector of vectors.filter(value => value.kind !== "grant.timestamp")) outputs.push([`fuzz/corpus/api_json/seed-${vector.id}`, vector.input]);
for (const [path, expected] of outputs) {
  const url = new URL(path, root);
  if (process.argv.includes("--check")) {
    const actual = await readFile(url, "utf8");
    if ((path.endsWith(".json") ? actual.replaceAll("\r\n", "\n") : actual) !== expected) throw new Error(`D-147 output stale: ${path}`);
  } else await writeFile(url, expected);
}
console.log(`validated ${vectors.length} D-147 Grant vectors and ${outputs.length - 1} parser seeds`);
