// SPDX-License-Identifier: Apache-2.0
// Independent D-136 JSON examples and parser-bound recipes; no Rust codec is called.
import { readFile, writeFile } from "node:fs/promises";
const root = new URL("../", import.meta.url);
const vectors = [];
const id = n => `019bdad6-b800-7000-8000-${String(n).padStart(12, "0")}`;
const time = "2026-11-01T00:00:00Z";
const create = { invitation_id: id(4), recipient_username: "recipient", roles: ["administrator", "member"], password_verifier: Buffer.alloc(32, 1).toString("base64url") };
const accept = { password: "1ABCDXYZ" };
const invitation = { id: id(4), etag: '"current"', created_at: time, updated_at: time, data: { organization_id: id(1), organization_name: "Operations", recipient_account_id: id(2), recipient_username: "recipient", roles: ["member"], issuer_account_id: id(3), expires_at: "2026-11-02T00:00:00Z", status: "pending", membership_id: null } };
const member = { id: id(5), etag: '"member"', created_at: time, updated_at: time, data: { organization_id: id(1), account_id: id(2), username: "recipient", roles: ["member"], status: "active" } };
const update = { roles: ["administrator", "member"], status: "suspended" };
const receipt = { invitation_id: id(4), organization_id: id(1), account_id: id(2), membership_id: id(5), accepted_at: time };
const dissolve = { organization_id: id(1) };
const dissolved = { organization_id: id(1), dissolved_at: time };
const page = item => ({ items: [item], next_cursor: null });
const examples = { create, accept, invitation, member, update, receipt, dissolve, dissolved, invitation_page: page(invitation), member_page: page(member) };
const json = JSON.stringify;
const add = (name, kind, input, expected = "rejected") => vectors.push({ id: `team-${name}-v1`, kind: `team.${kind}`, input: typeof input === "string" ? input : json(input), expected });
for (const [kind, value] of Object.entries(examples)) {
  add(kind, kind, value, json(value));
  add(`${kind}-whitespace`, kind, ` \t${json(value)} `, json(value));
  add(`${kind}-duplicate`, `${kind}.reject`, json(value).slice(0, -1) + ',"extra":{"x":1,"x":2}}');
  add(`${kind}-bom`, `${kind}.reject`, '\ufeff' + json(value));
}
const reverseRoles = value => { const copy = structuredClone(value); (copy.data ?? copy).roles.reverse(); return copy; };
for (const kind of ["create", "update"]) add(`${kind}-role-order`, kind, reverseRoles(examples[kind]), json(examples[kind]));
for (const kind of ["create", "accept", "update", "dissolve"]) {
  add(`${kind}-unknown`, `${kind}.reject`, { ...examples[kind], extra: true });
  const missing = structuredClone(examples[kind]); delete missing[Object.keys(missing)[0]];
  add(`${kind}-missing`, `${kind}.reject`, missing);
}
for (const kind of ["invitation", "member", "receipt", "dissolved", "invitation_page", "member_page"]) add(`${kind}-extensions`, kind, { ...examples[kind], extra: { version: 2 } }, json(examples[kind]));
for (const [name, value] of [
  ["unknown-role", { ...create, roles: ["custom"] }], ["duplicate-role", { ...create, roles: ["member", "member"] }],
  ["empty-role", { ...create, roles: [] }], ["username-case", { ...create, recipient_username: "Recipient" }],
  ["uuid-case", { ...create, invitation_id: id(4).toUpperCase() }], ["padded-verifier", { ...create, password_verifier: create.password_verifier + "=" }],
  ["short-verifier", { ...create, password_verifier: "AQ" }],
]) add(`create-${name}`, "create.reject", value);
for (const password of ["1abcdxyz", "1ABCDXYI", "1ABCDXYO", "1ABCDXYU", "1ABCDXYZ ", "1ABCDXY", "1ABCDXYZ0"]) add(`accept-invalid-${vectors.length}`, "accept.reject", { password });
add("update-removed", "update.reject", { ...update, status: "removed" });
for (const status of ["accepted", "revoked", "expired", "locked"]) {
  const value = structuredClone(invitation); value.data.status = status;
  if (status === "accepted") value.data.membership_id = id(5);
  add(`invitation-${status}`, "invitation", value, json(value));
}
const invalidState = structuredClone(invitation); invalidState.data.membership_id = id(5);
add("invitation-state-member", "invitation.reject", invalidState);
for (const kind of ["invitation_page", "member_page"]) {
  add(`${kind}-empty`, kind, { items: [], next_cursor: null }, '{"items":[],"next_cursor":null}');
  add(`${kind}-duplicates`, `${kind}.reject`, { ...examples[kind], items: [...examples[kind].items, ...examples[kind].items] });
  add(`${kind}-next-mismatch`, `${kind}.reject`, { ...examples[kind], next_cursor: id(99) });
  add(`${kind}-next-missing`, `${kind}.reject`, { items: [] });
}
const link = `https://sync.example.test/join-team#organization=${id(1)}&invitation=${id(4)}`;
add("link", "link", link, link);
for (const [name, value] of [["password", link + "&password=1ABCDXYZ"], ["http", link.replace("https:", "http:")], ["order", link.replace(`#organization=${id(1)}&invitation=${id(4)}`, `#invitation=${id(4)}&organization=${id(1)}`)]]) add(`link-${name}`, "link.reject", value);
const limits = { create: 4096, accept: 256, invitation: 4096, member: 4096, update: 1024, receipt: 1024, dissolve: 256, dissolved: 512, invitation_page: 2097152, member_page: 2097152 };
for (const [kind, bound] of Object.entries(limits)) for (const extra of [0, 1]) add(`${kind}-bound-${extra}`, "bound", { kind, base: json(examples[kind]), bytes: bound + extra }, extra ? "rejected" : "accepted");
const problem = { type: "about:blank", title: "Invitation not accepted", status: 409, detail: "The invitation is unavailable. Review the invitation or ask its issuer for a new one.", instance: "fixture-request", code: "organization.invitation_denied", changed: false, retryable: false };
add("invitation-denied", "problem", problem, json(problem));
const outputs = [["vectors/team-membership.json", JSON.stringify({ format: "scoplen-test-vectors", version: 1, vectors }, null, 2) + "\n"]];
for (const vector of vectors.filter(v => v.kind !== "team.bound")) outputs.push([`fuzz/corpus/api_json/seed-${vector.id}`, vector.input]);
for (const [kind, bound] of Object.entries(limits).filter(([, bound]) => bound < 2097152)) for (const extra of [0, 1]) {
  const base = json(examples[kind]);
  outputs.push([`fuzz/corpus/api_json/seed-team-${kind}-bound-${extra}`, " ".repeat(bound + extra - Buffer.byteLength(base)) + base]);
}
if (new Set(vectors.map(v => v.id)).size !== vectors.length) throw new Error("duplicate team vector id");
for (const [path, expected] of outputs) {
  const url = new URL(path, root);
  if (process.argv.includes("--check")) {
    const actual = await readFile(url, "utf8");
    if ((path.endsWith(".json") ? actual.replaceAll("\r\n", "\n") : actual) !== expected) throw new Error(`D-136 output stale: ${path}`);
  } else await writeFile(url, expected);
}
console.log(`validated ${vectors.length} D-136 API vectors and ${outputs.length - 1} parser seeds`);
