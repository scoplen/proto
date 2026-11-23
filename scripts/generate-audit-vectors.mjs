// SPDX-License-Identifier: Apache-2.0
// Independent D-144 writer: uses only Node JSON, Date and crypto, never Rust or schema helpers.
import { createHash, createPrivateKey, createPublicKey, sign } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";

const org = "0191d3e0-8000-7000-8000-000000000001";
const account = "0191d3e0-8000-7000-8000-000000000002";
const family = "0191d3e0-8000-7000-8000-000000000003";
const hash = bytes => createHash("sha256").update(bytes).digest();
const u64 = value => { const bytes = Buffer.alloc(8); bytes.writeBigUInt64BE(BigInt(value)); return bytes; };
const uuidBytes = text => Buffer.from(text.replaceAll("-", ""), "hex");
const privateKey = createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.alloc(32, 7)]), format: "der", type: "pkcs8" });
const publicKey = createPublicKey(privateKey).export({ format: "der", type: "spki" }).subarray(-32);

export function auditVectors() {
  const vectors = [];
  const add = (name, kind, input, expected) => vectors.push({ id: `audit-${name}-v1`, kind: `audit.${kind}`, input, expected });
  const json = (name, kind, value) => add(name, kind, JSON.stringify(value), JSON.stringify(value));
  const reject = (name, kind, value) => add(name, kind, typeof value === "string" ? value : JSON.stringify(value), "rejected");
  const event = { organization_id: org, sequence: "9007199254740993", occurred_at: "2026-11-17T00:00:00.001Z", category: "account_change", event_class: "organization.groups_created", outcome: "success", actor_account_id: account, actor_device_id: null, actor_browser_family_id: family, resource: { kind: "group", id: family }, previous_hash: Buffer.alloc(32).toString("hex"), event_hash: hash(Buffer.from("public projection fixture")).toString("hex") };
  json("browser-event", "event", event);
  json("unknown-event", "event", { ...event, sequence: "18446744073709551615", category: "unknown", event_class: "future.unclassified", outcome: "unknown", actor_account_id: null, actor_browser_family_id: null, resource: null });
  for (const key of Object.keys(event)) {
    const missing = { ...event }; delete missing[key]; reject(`event-missing-${key}`, "event", missing);
  }
  for (const key of ["organization_id", "sequence", "occurred_at", "category", "outcome", "previous_hash", "event_hash"]) reject(`event-null-${key}`, "event", { ...event, [key]: null });
  for (const [key, values] of Object.entries({ sequence: ["0", "01", "+1", "18446744073709551616", 9007199254740992], occurred_at: ["1970-01-01T00:00:00Z", "2026-02-30T00:00:00Z", "2026-11-17T00:00:00.010Z"], organization_id: [org.toUpperCase(), org.replace("-7000-", "-4000-")], category: [null, "future"], event_class: ["single", "future.<script>", "a."], outcome: [null, "ok"], actor_account_id: ["unknown"], previous_hash: ["A".repeat(64), "0".repeat(63)], resource: [{ kind: "unknown", id: family }, { kind: "group" }] })) {
    values.forEach((value, index) => reject(`event-${key}-${index}`, "event", { ...event, [key]: value }));
  }
  const extension = JSON.stringify({ ...event, extension: { ignored: true } });
  add("event-extension", "event", extension, JSON.stringify(event));
  reject("event-duplicate-extension", "event", JSON.stringify(event).replace(/}$/, ',"extension":{"x":1,"x":2}}'));
  reject("event-bom", "event", `\uFEFF${JSON.stringify(event)}`);
  const page = { items: [event, { ...event, sequence: "9007199254740992" }], next_cursor: "9007199254740992" };
  json("page", "page", page); json("empty-page", "page", { items: [], next_cursor: null });
  reject("page-ascending", "page", { ...page, items: [...page.items].reverse() });
  reject("page-duplicate", "page", { ...page, items: [event, event], next_cursor: event.sequence });
  reject("page-empty-cursor", "page", { items: [], next_cursor: "1" });
  reject("page-wrong-cursor", "page", { ...page, next_cursor: event.sequence });
  reject("page-missing-null-cursor", "page", { items: [] });
  reject("page-null-items", "page", { items: null, next_cursor: null });
  reject("page-numeric-cursor", "page", { ...page, next_cursor: 9007199254740992 });

  for (const text of ["0000-01-01T00:00:00Z", "0000-02-29T00:00:00.001Z", "1969-12-31T23:59:59.999Z", "1970-01-01T00:00:00Z", "2000-02-29T12:34:56.01Z", "2026-11-17T00:00:00.1Z", "9999-12-31T23:59:59.999Z"]) {
    const ms = Date.parse(text);
    if (!Number.isSafeInteger(ms)) throw new Error(`invalid independent timestamp ${text}`);
    add(`timestamp-${vectors.length}`, "timestamp", text, String(ms));
  }
  for (const text of ["1900-02-29T00:00:00Z", "2026-02-29T00:00:00Z", "2026-11-17T00:00:60Z", "2026-11-17T00:00:00.0Z", "2026-11-17T00:00:00.010Z", "2026-11-17T00:00:00.0001Z", "2026-11-17T00:00:00+00:00", "10000-01-01T00:00:00Z"]) reject(`timestamp-${vectors.length}`, "timestamp", text);

  const query = pairs => add(`query-${vectors.length}`, "query", JSON.stringify(pairs), "accepted");
  query([]); query([["limit", "500"], ["cursor", "18446744073709551615"], ["sort", "-sequence"]]);
  const clauses = ['occurred_at ge "2026-11-01T00:00:00Z"', 'occurred_at lt "2026-12-01T00:00:00Z"', `actor_account_id eq "${account}"`, `resource eq "group:${family}"`, 'event_class eq "future.unclassified"', 'outcome eq "unknown"'];
  clauses.forEach(clause => query([["filter", clause]])); query([["filter", clauses.join(" and ")]]);
  for (const pairs of [[["limit", "0"]], [["limit", "501"]], [["cursor", "01"]], [["cursor", "18446744073709551616"]], [["sort", "sequence"]], [["limit", "1"], ["limit", "2"]], [["from_sequence", "1"]], [["filter", ""]], [["filter", clauses[0] + " and " + clauses[0]]], [["filter", 'outcome eq "success" or outcome eq "failure"']], [["filter", 'outcome eq "suc\\cess"']], [["filter", 'event_class eq "é.event"']], [["filter", 'occurred_at ge "2026-12-01T00:00:00Z" and occurred_at lt "2026-11-01T00:00:00Z"']]]) reject(`query-${vectors.length}`, "query", JSON.stringify(pairs));
  for (const pairs of [[["from_sequence", "1"], ["to_sequence", "4096"]], [["from_sequence", "18446744073709551615"], ["to_sequence", "18446744073709551615"]]]) add(`range-${vectors.length}`, "range", JSON.stringify(pairs), "accepted");
  for (const pairs of [[], [["from_sequence", "0"], ["to_sequence", "1"]], [["from_sequence", "2"], ["to_sequence", "1"]], [["from_sequence", "1"], ["to_sequence", "4097"]], [["from_sequence", "1"], ["to_sequence", "18446744073709551615"]], [["from_sequence", "01"], ["to_sequence", "1"]], [["from_sequence", "1"], ["to_sequence", "1"], ["cursor", "1"]]]) reject(`range-${vectors.length}`, "range", JSON.stringify(pairs));
  for (const profile of ["device", "account-browser"]) {
    for (const path of ["/api/v1/orgs/{org}/audit-events", "/api/v1/orgs/{org}/audit-events/verify"]) {
      add(`operation-${vectors.length}`, "operation", JSON.stringify({ profile, method: "GET", path }), "audit:read");
      for (const method of ["POST", "PATCH", "DELETE", "get"]) add(`operation-${vectors.length}`, "operation", JSON.stringify({ profile, method, path }), "unmapped");
    }
    add(`operation-${vectors.length}`, "operation", JSON.stringify({ profile, method: "GET", path: "/api/v1/orgs/{org}/audit-events/{id}" }), "unmapped");
  }

  const original = Buffer.from('{"action":"organization.groups_created","account_id":"' + account + '","browser_family_id":"' + family + '"}');
  const head = hash(Buffer.concat([Buffer.alloc(32), original]));
  const checkpoint = ms => {
    const signed_at = new Date(ms).toISOString().replace(/\.000Z$/, "Z").replace(/(\.\d*?[1-9])0+Z$/, "$1Z");
    const payload = Buffer.concat([Buffer.from("spl-audit-checkpoint-v1"), uuidBytes(org), u64(1), head, u64(ms)]);
    const evidence = { sequence: "1", head_hash: head.toString("hex"), signed_at, signature: sign(null, payload, privateKey).toString("base64url") };
    add(`checkpoint-${ms % 1000}`, "checkpoint", JSON.stringify({ organization_id: org, checkpoint: evidence, public_key: publicKey.toString("hex"), original_event_hex: original.toString("hex") }), payload.toString("hex"));
    return evidence;
  };
  const checkpoints = [0, 1, 10, 100, 999].map(part => checkpoint(1794873600000 + part));
  const verification = { organization_id: org, from_sequence: "1", to_sequence: "1", checked_events: "1", valid: true, failure_sequence: null, previous_hash: Buffer.alloc(32).toString("hex"), head_hash: head.toString("hex"), checkpoint: checkpoints[0], uncheckpointed_from_sequence: null };
  json("verification-checkpoint", "verification", verification);
  json("verification-unsigned", "verification", { ...verification, checkpoint: null, uncheckpointed_from_sequence: "1" });
  json("verification-failure", "verification", { ...verification, checked_events: "0", valid: false, failure_sequence: "1", previous_hash: null, head_hash: null, checkpoint: null, uncheckpointed_from_sequence: null });
  for (const key of Object.keys(verification)) { const missing = { ...verification }; delete missing[key]; reject(`verification-missing-${key}`, "verification", missing); }
  for (const key of ["organization_id", "from_sequence", "to_sequence", "checked_events", "valid"]) reject(`verification-null-${key}`, "verification", { ...verification, [key]: null });
  for (const key of Object.keys(checkpoints[0])) { const missing = { ...checkpoints[0] }; delete missing[key]; reject(`checkpoint-missing-${key}`, "verification", { ...verification, checkpoint: missing }); }
  for (const [key, value] of [["checked_events", "0"], ["failure_sequence", "1"], ["previous_hash", null], ["head_hash", "1".repeat(64)], ["uncheckpointed_from_sequence", "1"]]) reject(`verification-${key}`, "verification", { ...verification, [key]: value });
  reject("verification-signature-padding", "verification", { ...verification, checkpoint: { ...checkpoints[0], signature: checkpoints[0].signature + "==" } });
  const grantId = "0191d3e0-8000-7000-8000-000000000004";
  const grantEvents = ["deleted", "updated", "created"].map((action, index) => ({ ...event,
    sequence: String(BigInt(event.sequence) - BigInt(index)), category: "authorization",
    event_class: `organization.grants_${action}`, resource: { kind: "grant", id: grantId },
  }));
  grantEvents.forEach(value => json(value.event_class.replace("organization.", ""), "event", value));
  json("grant-page", "page", { items: grantEvents, next_cursor: null });
  add("grant-resource-filter", "query", JSON.stringify([["filter", `resource eq "grant:${grantId}"`]]), "accepted");
  for (const kind of ["Grant", "grants", "grant-extra"]) {
    reject(`grant-kind-${kind}`, "event", { ...grantEvents[0], resource: { kind, id: grantId } });
    reject(`grant-filter-${kind}`, "query", JSON.stringify([["filter", `resource eq "${kind}:${grantId}"`]]));
  }
  const requestEvents = ["created", "approved", "denied", "cancelled", "expired"].map((action, index) => ({ ...event,
    sequence: String(BigInt(event.sequence) - BigInt(index)), category: "authorization",
    event_class: `organization.access_request_${action}`, resource: { kind: "access_request", id: grantId },
    ...(action === "expired" ? { actor_account_id: null, actor_browser_family_id: null } : {}),
  }));
  requestEvents.forEach(value => json(value.event_class.replace("organization.", ""), "event", value));
  json("access-request-page", "page", { items: requestEvents, next_cursor: null });
  add("access-request-resource-filter", "query", JSON.stringify([["filter", `resource eq "access_request:${grantId}"`]]), "accepted");
  for (const kind of ["AccessRequest", "access-requests", "access_request_extra"]) {
    reject(`access-request-kind-${kind}`, "event", { ...requestEvents[0], resource: { kind, id: grantId } });
    reject(`access-request-filter-${kind}`, "query", JSON.stringify([["filter", `resource eq "${kind}:${grantId}"`]]));
  }
  const device = "0191d3e0-8000-7000-8000-000000000005";
  const firstDraft = "0191d3e0-8000-7000-8000-000000000006";
  const nextDraft = "0191d3e0-8000-7000-8000-000000000007";
  let previous = Buffer.alloc(32);
  const draftEvents = [
    ["created", firstDraft, { device_id: device }],
    ["cancelled", firstDraft, { browser_family_id: family }],
    ["created", nextDraft, { device_id: device }],
  ].map(([verb, generation, writer], index) => {
    const action = `organization.auth_draft_${verb}`;
    const original = Buffer.from(JSON.stringify({ action, account_id: account, organization_id: org, generation, ...writer }));
    const digest = hash(Buffer.concat([previous, original]));
    const projection = { ...event, sequence: String(index + 1), category: "scoplen", event_class: action,
      actor_device_id: writer.device_id ?? null, actor_browser_family_id: writer.browser_family_id ?? null,
      resource: { kind: "auth_connection_draft", id: generation },
      previous_hash: previous.toString("hex"), event_hash: digest.toString("hex") };
    previous = digest;
    return projection;
  });
  json("auth-draft-device-create", "event", draftEvents[0]);
  json("auth-draft-browser-cancel", "event", draftEvents[1]);
  json("auth-draft-history", "page", { items: draftEvents.toReversed(), next_cursor: null });
  add("auth-draft-generation-filter", "query", JSON.stringify([["filter", `resource eq "auth_connection_draft:${firstDraft}" and event_class eq "organization.auth_draft_created"`]]), "accepted");
  for (const kind of ["AuthConnectionDraft", "auth-connection-draft", "auth_connection_drafts"]) {
    reject(`auth-draft-kind-${kind}`, "event", { ...draftEvents[0], resource: { kind, id: firstDraft } });
    reject(`auth-draft-filter-${kind}`, "query", JSON.stringify([["filter", `resource eq "${kind}:${firstDraft}"`]]));
  }
  return vectors;
}

const vectors = auditVectors();
const outputs = [["vectors/audit.json", JSON.stringify({ format: "scoplen-test-vectors", version: 1, vectors }, null, 2) + "\n"]];
for (const vector of vectors.filter(v => ["audit.event", "audit.page", "audit.verification", "audit.query", "audit.range"].includes(v.kind))) {
  if (vector.input.length < 4096) outputs.push([`fuzz/corpus/api_json/seed-${vector.id}`, vector.input]);
}
for (const [path, expected] of outputs) {
  const url = new URL(`../${path}`, import.meta.url);
  if (process.argv.includes("--check")) {
    if ((await readFile(url, "utf8")).replaceAll("\r\n", "\n") !== expected) throw new Error(`D-144 stale output: ${path}`);
  } else await writeFile(url, expected);
}
console.log(`validated ${vectors.length} independent Audit vectors`);
