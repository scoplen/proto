// SPDX-License-Identifier: Apache-2.0
// Independent D-150 producer; no Rust codec or generated OpenAPI code is called.
import { readFile, writeFile } from "node:fs/promises";

const root = new URL("../", import.meta.url), json = JSON.stringify;
const id = n => `019bdad6-b800-7000-8000-${String(n).padStart(12, "0")}`;
const fields = { host: id(3), remote_user: "deploy", duration_seconds: 300, reason: "Routine maintenance" };
const resource = { id: id(4), etag: '"current"', created_at: "2026-11-01T00:00:00.123456789Z", updated_at: "2026-11-01T00:00:00.123456789Z",
  data: { requester_account_id: id(1), requester_membership_id: id(2), ...fields,
    expires_at: "2026-11-02T00:00:00.123456789Z", status: "pending", decision: null, grant: null } };
const examples = { fields, check_request: { data: fields }, check_response: { allowed: true },
  create: { id: id(4), data: fields }, decision: { decision: "approve" }, resource,
  page: { items: [resource], next_cursor: null } };
const vectors = [];
const add = (name, kind, input, expected = "rejected") => vectors.push({ id: `access-request-${name}-v1`, kind: `access_request.${kind}`, input: typeof input === "string" ? input : json(input), expected });
for (const [kind, value] of Object.entries(examples)) {
  add(kind, kind, value, json(value));
  add(`${kind}-whitespace`, kind, ` \t${json(value)}\n`, json(value));
  add(`${kind}-missing`, kind, {});
  add(`${kind}-null`, kind, null);
  add(`${kind}-duplicate`, kind, json(value).slice(0, -1) + ',"future":{"x":1,"x":2}}');
  add(`${kind}-extension`, kind, { ...value, future: true }, ["check_response", "resource", "page"].includes(kind) ? json(value) : "rejected");
}
for (const kind of ["fields", "check_request", "create", "resource"]) {
  const change = data => kind === "fields" ? data : { ...examples[kind], data: kind === "resource" ? { ...resource.data, ...data } : data };
  for (const [name, replacement, accept] of [
    ["exact-user", { remote_user: " e\u0301 " }, true], ["max-user", { remote_user: "é".repeat(127) + "x" }, true],
    ["long-user", { remote_user: "é".repeat(128) }, false], ["empty-user", { remote_user: "" }, false], ["control-user", { remote_user: "a\u0085b" }, false],
    ["min-duration", { duration_seconds: 1 }, true], ["max-duration", { duration_seconds: 86400 }, true],
    ["zero-duration", { duration_seconds: 0 }, false], ["long-duration", { duration_seconds: 86401 }, false],
    ["fraction-duration", { duration_seconds: 1.5 }, false], ["string-duration", { duration_seconds: "300" }, false],
    ["exact-reason", { reason: "  é\n\tgo  " }, true], ["max-reason", { reason: "é".repeat(1024) }, true],
    ["long-reason", { reason: "é".repeat(1025) }, false], ["empty-reason", { reason: "" }, false],
    ["whitespace-reason", { reason: " \t\n\u2003" }, false], ["cr-reason", { reason: "go\rnow" }, false],
    ["control-reason", { reason: "go\u007fnow" }, false], ["bad-host", { host: id(3).toUpperCase() }, false],
    ["wrong-host-version", { host: id(3).replace("-7000-", "-4000-") }, false],
  ]) {
    const changed = change({ ...fields, ...replacement }); add(`${kind}-${name}`, kind, changed, accept ? json(changed) : "rejected");
  }
  for (const field of Object.keys(fields)) {
    const changed = structuredClone(examples[kind]); const data = kind === "fields" ? changed : changed.data;
    delete data[field]; add(`${kind}-missing-${field}`, kind, changed);
    const nulled = structuredClone(examples[kind]); (kind === "fields" ? nulled : nulled.data)[field] = null;
    add(`${kind}-null-${field}`, kind, nulled);
  }
  const extended = change({ ...fields, future: true });
  add(`${kind}-nested-extension`, kind, extended, kind === "resource" ? json(resource) : "rejected");
  add(`${kind}-duplicate-reason`, kind, json(examples[kind]).replace('"reason":"Routine maintenance"', '"reason":"Routine maintenance","reason":"other"'));
}
add("decision-deny", "decision", { decision: "deny" }, '{"decision":"deny"}');
for (const decision of [null, "approved", "Approve", true]) add(`decision-bad-${decision}`, "decision", { decision });
add("decision-reason", "decision", { decision: "approve", reason: "extra" });
add("check-response-false", "check_response", { allowed: false }, '{"allowed":false}');
add("check-response-null", "check_response", { allowed: null });

const denied = { ...resource, data: { ...resource.data, status: "denied", decision: { outcome: "deny", actor_account_id: id(9), decided_at: "2026-11-01T01:00:00.987654321Z" } } };
const from = Math.floor(Date.parse("2026-11-01T01:00:00Z") / 1000);
const time = seconds => new Date(seconds * 1000).toISOString().replace(".000Z", "Z");
const approved = { ...resource, data: { ...resource.data, status: "approved", decision: { ...denied.data.decision, outcome: "approve" }, grant: { id: id(10), valid_from: time(from), valid_until: time(from + fields.duration_seconds) } } };
for (const status of ["expired", "cancelled", "revoked", "future_state_2"]) {
  const changed = { ...resource, data: { ...resource.data, status } }; add(`resource-${status}`, "resource", changed, json(changed));
}
add("resource-denied", "resource", denied, json(denied)); add("resource-approved", "resource", approved, json(approved));
for (const [name, changed] of [
  ["pending-decision", { ...resource, data: { ...resource.data, decision: denied.data.decision } }],
  ["denied-grant", { ...denied, data: { ...denied.data, grant: approved.data.grant } }],
  ["approved-no-grant", { ...approved, data: { ...approved.data, grant: null } }],
  ["approved-deny", { ...approved, data: { ...approved.data, decision: denied.data.decision } }],
  ["wrong-grant-start", { ...approved, data: { ...approved.data, grant: { ...approved.data.grant, valid_from: time(from + 1), valid_until: time(from + 301) } } }],
  ["wrong-grant-length", { ...approved, data: { ...approved.data, grant: { ...approved.data.grant, valid_until: time(from + 301) } } }],
  ["fractional-grant", { ...approved, data: { ...approved.data, grant: { ...approved.data.grant, valid_from: time(from).replace("Z", ".0Z") } } }],
  ["wrong-deadline", { ...resource, data: { ...resource.data, expires_at: "2026-11-02T00:00:00.123456788Z" } }],
  ["rounded-deadline", { ...resource, data: { ...resource.data, expires_at: "2026-11-02T00:00:00Z" } }],
  ["bad-status", { ...resource, data: { ...resource.data, status: "Pending" } }],
  ["long-status", { ...resource, data: { ...resource.data, status: "a".repeat(65) } }],
  ["weak-etag", { ...resource, etag: 'W/"current"' }],
]) add(`resource-${name}`, "resource", changed);
for (const [name, created, expires] of [
  ["leap-day", "2000-02-28T23:59:59.123Z", "2000-02-29T23:59:59.1230Z"],
  ["century", "2100-02-28T00:00:00Z", "2100-03-01T00:00:00Z"],
  ["year-zero", "0000-02-28T00:00:00Z", "0000-02-29T00:00:00Z"],
  ["year-bound", "9999-12-30T00:00:00Z", "9999-12-31T00:00:00Z"],
]) {
  const changed = { ...resource, created_at: created, updated_at: created, data: { ...resource.data, expires_at: expires } };
  add(`resource-${name}`, "resource", changed, json(changed));
}
for (const field of Object.keys(resource.data)) {
  const changed = structuredClone(resource); delete changed.data[field]; add(`resource-data-missing-${field}`, "resource", changed);
}
const extended = { ...approved, data: { ...approved.data, decision: { ...approved.data.decision, future: true }, grant: { ...approved.data.grant, future: true } } };
add("resource-decision-grant-extension", "resource", extended, json(approved));
add("page-empty", "page", { items: [], next_cursor: null }, '{"items":[],"next_cursor":null}');
add("page-continuation", "page", { items: [resource], next_cursor: resource.id }, json({ items: [resource], next_cursor: resource.id }));
add("page-duplicate-items", "page", { items: [resource, resource], next_cursor: null });
add("page-reversed", "page", { items: [{ ...resource, id: id(5) }, resource], next_cursor: null });
add("page-wrong-cursor", "page", { items: [resource], next_cursor: id(99) });
add("page-empty-cursor", "page", { items: [], next_cursor: resource.id });
add("page-missing-cursor", "page", { items: [] });
const pad = (text, max) => text + " ".repeat(max + 1 - Buffer.byteLength(text));
add("create-original-overflow", "create", pad(json(examples.create), 4096));
add("resource-original-overflow", "resource", pad(json(resource), 8192));
add("page-original-item-overflow", "page", '{"items":[' + json(resource).slice(0, -1) + ',"future":"' + "x".repeat(8192) + '"}],"next_cursor":null}');
for (const [name, input, expected] of [
  ["mine", [["view", "mine"]], { view: "mine", limit: 50, cursor: null }],
  ["approvals", [["view", "approvals"], ["limit", "1"], ["cursor", id(4)]], { view: "approvals", limit: 1, cursor: id(4) }],
  ["missing-view", [], null], ["duplicate-view", [["view", "mine"], ["view", "mine"]], null],
  ["unknown-view", [["view", "all"]], null], ["sort", [["view", "mine"], ["sort", "id"]], null],
  ["bad-limit", [["view", "mine"], ["limit", "501"]], null],
  ["duplicate-limit", [["view", "mine"], ["limit", "1"], ["limit", "2"]], null],
  ["bad-cursor", [["view", "mine"], ["cursor", "opaque"]], null],
]) add(`query-${name}`, "query", input, expected === null ? "rejected" : json(expected));

if (new Set(vectors.map(value => value.id)).size !== vectors.length) throw new Error("duplicate vector id");
const outputs = [["vectors/access-request.json", json({ format: "scoplen-test-vectors", version: 1, vectors }, null, 2) + "\n"]];
for (const vector of vectors) outputs.push([`fuzz/corpus/api_json/seed-${vector.id}`, vector.input]);
for (const [path, expected] of outputs) {
  const url = new URL(path, root);
  if (process.argv.includes("--check")) {
    const actual = await readFile(url, "utf8");
    if ((path.endsWith(".json") ? actual.replaceAll("\r\n", "\n") : actual) !== expected) throw new Error(`D-150 output stale: ${path}`);
  } else await writeFile(url, expected);
}
console.log(`validated ${vectors.length} D-150 access-request vectors and ${outputs.length - 1} parser seeds`);
