// SPDX-License-Identifier: Apache-2.0
// Independent D-137 JSON and Cedar examples; no Rust implementation is called.
import { readFile, writeFile } from "node:fs/promises";

const root = new URL("../", import.meta.url);
const vectors = [];
const id = n => `019bdad6-b800-7000-8000-${String(n).padStart(12, "0")}`;
const time = "2026-11-01T00:00:00Z";
const source = 'permit(principal, action == Action::"view_inventory", resource);';
const groupFields = { name: "Operations", members: [id(2), id(3)] };
const policyFields = { name: "Read hosts", source, enabled: true };
const envelope = (n, data) => ({ id: id(n), etag: '"current"', created_at: time, updated_at: time, data });
const examples = {
  group_create: { id: id(4), data: groupFields }, group_replace: { data: groupFields },
  group_resource: envelope(4, { ...groupFields, source: "local" }),
  group_page: { items: [envelope(4, { ...groupFields, source: "local" })], next_cursor: null },
  policy_create: { id: id(5), data: policyFields }, policy_replace: { data: policyFields },
  policy_resource: envelope(5, policyFields), policy_page: { items: [envelope(5, policyFields)], next_cursor: null },
};
const json = JSON.stringify;
const add = (name, kind, input, expected = "rejected") => vectors.push({ id: `group-policy-${name}-v1`, kind: `group_policy.${kind}`, input: typeof input === "string" ? input : json(input), expected });
for (const [kind, value] of Object.entries(examples)) {
  add(kind, kind, value, json(value));
  add(`${kind}-whitespace`, kind, ` \t${json(value)}`, json(value));
  add(`${kind}-duplicate`, kind, json(value).slice(0, -1) + ',"extra":{"x":1,"x":2}}');
  add(`${kind}-missing`, kind, {});
  if (kind.endsWith("resource") || kind.endsWith("page")) add(`${kind}-extension`, kind, { ...value, future: { version: 2 } }, json(value));
  else add(`${kind}-extension`, kind, { ...value, future: true });
}
for (const kind of ["group_create", "group_replace", "group_resource"]) {
  const value = structuredClone(examples[kind]); value.data.members.reverse();
  add(`${kind}-member-order`, kind, value, json(examples[kind]));
  value.data.members = [id(2), id(2)]; add(`${kind}-duplicate-member`, kind, value);
  value.data.members = [id(2).toUpperCase()]; add(`${kind}-uuid-case`, kind, value);
  value.data.members = []; add(`${kind}-empty-members`, kind, value, json(value));
}
for (const kind of ["group_create", "group_replace"]) {
  add(`${kind}-source`, kind, { ...examples[kind], data: { ...groupFields, source: "local" } });
  add(`${kind}-nested-extension`, kind, { ...examples[kind], data: { ...groupFields, more: false } });
}
add("group-resource-idp", "group_resource", envelope(4, { ...groupFields, source: "IdP" }), json(envelope(4, { ...groupFields, source: "IdP" })));
add("group-resource-unknown-source", "group_resource", envelope(4, { ...groupFields, source: "idp" }));
for (const kind of ["group_page", "policy_page"]) {
  add(`${kind}-empty`, kind, { items: [], next_cursor: null }, '{"items":[],"next_cursor":null}');
  add(`${kind}-missing-cursor`, kind, { items: [] });
  add(`${kind}-duplicate-items`, kind, { items: [examples[kind].items[0], examples[kind].items[0]], next_cursor: null });
  add(`${kind}-wrong-cursor`, kind, { ...examples[kind], next_cursor: id(99) });
}
for (const kind of ["policy_create", "policy_replace"]) {
  for (const [name, fields] of [
    ["non-bool", { ...policyFields, enabled: 1 }], ["source-empty", { ...policyFields, source: "" }],
    ["unknown-action", { ...policyFields, source: 'permit(principal, action == Action::"future_action", resource);' }],
    ["source-template", { ...policyFields, source: 'permit(principal == ?principal, action, resource);' }],
    ["source-multiple", { ...policyFields, source: source + source }], ["nested-extension", { ...policyFields, roles: ["owner"] }],
  ]) add(`${kind}-${name}`, kind, { ...examples[kind], data: fields });
}
for (const [name, policy, expected] of [
  ["view", source, "accepted"],
  ["view-time", 'permit(principal, action == Action::"view_inventory", resource) when { context.now > 1 };', "rejected"],
  ["view-forbid-time", 'forbid(principal, action == Action::"view_inventory", resource) unless { context["now"] > 1 };', "rejected"],
  ["view-set-time", 'permit(principal, action in [Action::"connect", Action::"view_inventory"], resource) when { context.now > 1 };', "rejected"],
  ["view-unconstrained-time", 'forbid(principal, action, resource) when { context.now > 1 };', "rejected"],
  ["view-condition-action-time", 'permit(principal, action, resource) when { [Action::"view_inventory"].contains(action) && context.now > 1 };', "rejected"],
  ["view-has-time", 'permit(principal, action == Action::"view_inventory", resource) when { context has now };', "rejected"],
  ["view-context-value", 'permit(principal, action == Action::"view_inventory", resource) when { context == context };', "rejected"],
  ["connect-time", 'permit(principal, action == Action::"connect", resource) when { context.now > 1 };', "accepted"],
  ["connect-forbid-time", 'forbid(principal, action in [Action::"connect"], resource) when { context.now > 1 };', "accepted"],
  ["view-comment", '// context.now is prose\n' + source, "accepted"],
  ["view-string", 'permit(principal, action == Action::"view_inventory", resource) when { "context.now" == "context.now" };', "accepted"],
]) add(`profile-${name}`, "profile", policy, expected);

for (const [name, policy, observes] of [
  ["permit", 'permit(principal, action == Action::"connect", resource) when { context.source_ip == "192.0.2.1" };', true],
  ["forbid-bracket", 'forbid(principal, action == Action::"connect", resource) unless { context["source_ip"] == "192.0.2.1" };', true],
  ["has", 'permit(principal, action in [Action::"connect"], resource) when { context has source_ip };', true],
  ["unconstrained", 'forbid(principal, action, resource) when { action == Action::"connect" && context has source_ip };', true],
  ["action-set", 'permit(principal, action in [Action::"view_inventory", Action::"connect"], resource) when { if action == Action::"connect" then context.source_ip == "192.0.2.1" else true };', true],
  ["indirect-context", 'permit(principal, action == Action::"connect", resource) when { (if true then context else context).source_ip == "192.0.2.1" };', true],
  ["whole-context", 'forbid(principal, action == Action::"connect", resource) when { context == context };', true],
  ["ordinary", 'permit(principal, action == Action::"connect", resource);', false],
  ["other-action", 'permit(principal, action == Action::"view_policy", resource) when { context == context };', false],
  ["comment", 'permit(principal, action == Action::"connect", resource); // context.source_ip', false],
  ["string", 'permit(principal, action == Action::"connect", resource) when { "context.source_ip" == "context.source_ip" };', false],
  ["other-fields", 'permit(principal, action == Action::"connect", resource) when { context.remote_user == "source_ip" && context.now > 1 };', false],
]) add(`connect-source-ip-${name}`, "connect_source_ip", policy, String(observes));

const kinds = { 1: "Host", 2: "AccessProfile", 4: "Route", 5: "HostGroup", 6: "TrustRecord", 7: "Snippet", 11: "GatewayNetwork" };
const sorted = values => [...values].sort();
const canonical = value => {
  const result = {};
  if (value.connect) result.connect = { host_groups: sorted(value.connect.host_groups), hosts: sorted(value.connect.hosts), remote_user: value.connect.remote_user };
  if (value.group) result.group = value.group;
  if (value.membership) result.membership = value.membership;
  result.organization = value.organization;
  if (value.view) result.view = [...value.view].sort((a, b) => a.type - b.type || a.id.localeCompare(b.id)).map(item => ({ id: item.id, type: item.type }));
  return result;
};
const generate = value => {
  const subject = value.membership ? `context.membership == Membership::"${value.membership}"` : `context.membership.groups.contains(Group::"${value.group}")`;
  let action, target;
  if (value.view) {
    action = "view_inventory";
    const selectors = canonical(value).view;
    target = `(${Object.keys(kinds).map(Number).filter(type => selectors.some(item => item.type === type)).map(type => `(resource is ${kinds[type]} && [${selectors.filter(item => item.type === type).map(item => `${kinds[type]}::"${item.id}"`).join(", ")}].contains(resource))`).join(" || ")})`;
  } else {
    action = "connect";
    const selectors = [];
    if (value.connect.hosts.length) selectors.push(`[${sorted(value.connect.hosts).map(value => `Host::"${value}"`).join(", ")}].contains(resource)`);
    selectors.push(...sorted(value.connect.host_groups).map(value => `resource.host_groups.contains(HostGroup::"${value}")`));
    target = `(${selectors.join(" || ")}) && context.remote_user == ${json(value.connect.remote_user)}`;
  }
  return `permit(principal is Account, action == Action::"${action}", resource)\nwhen {\n    context.organization == Organization::"${value.organization}" &&\n    ${subject} &&\n    ${target}\n};`;
};
const simple = [
  ["member-view", { organization: id(1), membership: id(2), view: [{ type: 7, id: id(6) }, { type: 1, id: id(5) }] }],
  ["group-view", { organization: id(1), group: id(3), view: [{ type: 1, id: id(5) }] }],
  ["all-inventory-types", { organization: id(1), membership: id(2), view: Object.keys(kinds).map(type => ({ type: Number(type), id: id(10 + Number(type)) })) }],
  ["member-connect", { organization: id(1), membership: id(2), connect: { hosts: [id(6), id(5)], host_groups: [], remote_user: "deploy" } }],
  ["group-connect", { organization: id(1), group: id(3), connect: { hosts: [], host_groups: [id(9), id(8)], remote_user: "operator" } }],
  ["escaped-connect", { organization: id(1), group: id(3), connect: { hosts: [id(5)], host_groups: [id(8)], remote_user: 'deploy\\"é' } }],
  ["maximum-view", { organization: id(1), membership: id(2), view: Array.from({ length: 64 }, (_, i) => ({ type: 1, id: id(i + 10) })) }],
  ["maximum-connect", { organization: id(1), group: id(3), connect: { hosts: Array.from({ length: 64 }, (_, i) => id(i + 10)), host_groups: Array.from({ length: 64 }, (_, i) => id(i + 100)), remote_user: "x".repeat(255) } }],
];
for (const [name, value] of simple) {
  add(`simple-${name}`, "simple_input", value, json(canonical(value)));
  add(`source-${name}`, "simple_source", value, generate(value));
}
const base = simple[0][1];
for (const [name, value] of [
  ["two-subjects", { ...base, group: id(3) }], ["missing-subject", { organization: id(1), view: base.view }],
  ["two-rules", { ...base, connect: simple[3][1].connect }], ["empty-view", { ...base, view: [] }],
  ["duplicate-view", { ...base, view: [base.view[0], base.view[0]] }], ["credential", { ...base, view: [{ type: 3, id: id(4) }] }],
  ["future-type", { ...base, view: [{ type: 12, id: id(4) }] }], ["unknown-field", { ...base, roles: ["owner"] }],
  ["empty-connect", { organization: id(1), group: id(3), connect: { hosts: [], host_groups: [], remote_user: "deploy" } }],
  ["control-user", { organization: id(1), group: id(3), connect: { hosts: [id(5)], host_groups: [], remote_user: "bad\nuser" } }],
  ["excess-view", { ...base, view: Array.from({ length: 65 }, (_, i) => ({ type: 1, id: id(i + 10) })) }],
]) add(`simple-${name}`, "simple_input", value);
add("simple-float-type", "simple_input", json(base).replace('"type":7', '"type":7.0'));

const outputs = [["vectors/group-policy.json", json({ format: "scoplen-test-vectors", version: 1, vectors }, null, 2) + "\n"]];
for (const vector of vectors.filter(value => !["group_policy.profile", "group_policy.connect_source_ip"].includes(value.kind))) outputs.push([`fuzz/corpus/api_json/seed-${vector.id}`, vector.input]);
for (const [path, expected] of outputs) {
  const url = new URL(path, root);
  if (process.argv.includes("--check")) {
    const actual = await readFile(url, "utf8");
    if ((path.endsWith(".json") ? actual.replaceAll("\r\n", "\n") : actual) !== expected) throw new Error(`D-137 output stale: ${path}`);
  } else await writeFile(url, expected);
}
if (new Set(vectors.map(value => value.id)).size !== vectors.length) throw new Error("duplicate vector id");
console.log(`validated ${vectors.length} D-137 group/policy vectors and ${outputs.length - 1} parser seeds`);
