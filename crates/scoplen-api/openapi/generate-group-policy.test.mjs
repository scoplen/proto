// SPDX-License-Identifier: Apache-2.0
import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { generateGroupPolicyTypes, groupPolicyDefinitions } from "./generate-group-policy.mjs";

function document() {
  const { schemas, responses, paths } = structuredClone(groupPolicyDefinitions());
  return { components: { schemas, responses }, paths };
}
const groups = "/orgs/{org}/groups";
const group = `${groups}/{id}`;
const policies = "/orgs/{org}/policies";
const policy = `${policies}/{id}`;

test("D-137 authored OpenAPI and public exports contain the complete shared contract", async () => {
  const authored = JSON.parse(await readFile(new URL("v1.yaml", import.meta.url), "utf8"));
  const types = await readFile(new URL("types.ts", import.meta.url), "utf8");
  const index = await readFile(new URL("index.ts", import.meta.url), "utf8");
  assert.equal(generateGroupPolicyTypes(authored), generateGroupPolicyTypes(document()));
  assert.match(types, /put\?: unknown/);
  const registry = types.slice(types.indexOf("export interface components"), types.indexOf("export interface Resource"));
  for (const name of Object.keys(groupPolicyDefinitions().schemas)) {
    assert.match(registry, new RegExp(`^    ${name}: ${name};$`, "m"));
    assert.match(index, new RegExp(`^  ${name},$`, "m"));
  }
  for (const name of ["SimpleRuleSubject", "SimpleRule"]) assert.match(index, new RegExp(`^  ${name},$`, "m"));
  for (const name of ["Group", "Policy"]) {
    assert.ok(!Object.hasOwn(authored.components.schemas, name));
    assert.doesNotMatch(registry, new RegExp(`^    ${name}: Resource;$`, "m"));
  }
});

test("D-137 generates exact public group, policy and independent simple-rule types", () => {
  const types = generateGroupPolicyTypes(document());
  for (const name of ["GroupFields", "GroupCreateRequest", "GroupReplaceRequest", "GroupResource", "GroupPage", "PolicyFields", "PolicyCreateRequest", "PolicyReplaceRequest", "PolicyResource", "PolicyPage", "SimpleRuleSelector", "SimpleRuleConnect"]) assert.match(types, new RegExp(`export interface ${name} `));
  for (const name of ["GroupSource", "SimpleRuleSubject", "SimpleRule", "SimpleRuleInput", "GroupPolicyBodyTooLargeProblem"]) assert.match(types, new RegExp(`export type ${name} =`));
  assert.match(types, /data: GroupFields & \{ source: GroupSource; \[extension: string\]: unknown \}/);
  assert.match(types, /view: SimpleRuleSelector\[\]; connect\?: never/);
  assert.match(types, /connect: SimpleRuleConnect; view\?: never/);
  assert.match(types, /membership: string; group\?: never/);
  assert.match(types, /type: 1 \| 2 \| 4 \| 5 \| 6 \| 7 \| 11/);
  assert.doesNotMatch(types, /interface GroupFields \{[^}]*source:/);
  assert.equal(Object.keys(groupPolicyDefinitions().paths).length, 4);
  assert.equal(Object.values(groupPolicyDefinitions().paths).flatMap(path => Object.keys(path)).length, 10);
  assert.ok(!Object.hasOwn(groupPolicyDefinitions().paths[group], "patch"));
  assert.ok(!Object.hasOwn(groupPolicyDefinitions().paths, `${policies}/evaluate`));
});

test("D-137 definitions capture strict requests, tolerant bounded responses and exact generator alternatives", () => {
  const { schemas, paths } = groupPolicyDefinitions();
  for (const name of ["GroupFields", "GroupCreateRequest", "GroupReplaceRequest", "PolicyFields", "PolicyCreateRequest", "PolicyReplaceRequest", "SimpleRuleSelector", "SimpleRuleConnect"]) assert.equal(schemas[name].additionalProperties, false);
  for (const name of ["GroupResource", "GroupPage", "PolicyResource", "PolicyPage"]) assert.equal(schemas[name].additionalProperties, true);
  assert.equal(schemas.GroupResource.properties.data.additionalProperties, true);
  assert.equal(schemas.GroupFields.properties.members.maxItems, 4096);
  assert.equal(schemas.PolicyFields.properties.source["x-scoplen-max-utf8-bytes"], 65536);
  assert.equal(schemas.SimpleRuleInput.oneOf.length, 4);
  for (const alternative of schemas.SimpleRuleInput.oneOf) {
    assert.equal(alternative.additionalProperties, false);
    assert.equal(alternative.required.length, 3);
    assert.ok(alternative.required.includes("organization"));
    assert.equal(alternative.required.filter(key => ["membership", "group"].includes(key)).length, 1);
    assert.equal(alternative.required.filter(key => ["view", "connect"].includes(key)).length, 1);
  }
  for (const path of Object.values(paths)) for (const operation of Object.values(path)) assert.deepEqual(operation.security, [{ accessToken: [], dpopProof: [] }]);
});

test("D-137 read authority is separate from writes and view/connect generation", () => {
  const { paths, schemas } = groupPolicyDefinitions();
  for (const path of [groups, group]) {
    assert.equal(paths[path].get["x-scoplen-required-device-scope"], "policies:read");
    assert.deepEqual(paths[path].get["x-scoplen-accepted-cedar-actions"], ["view_policy", "manage_members"]);
  }
  assert.equal(paths[groups].post["x-scoplen-required-device-scope"], "teams:manage");
  assert.equal(paths[group].put["x-scoplen-cedar-action"], "manage_members");
  assert.equal(paths[policies].get["x-scoplen-cedar-action"], "view_policy");
  assert.equal(paths[policies].post["x-scoplen-required-device-scope"], "policies:write");
  assert.equal(paths[policy].put["x-scoplen-cedar-action"], "manage_policy");
  assert.match(schemas.SimpleRuleInput.description, /dependency-read grants/);
  assert.match(schemas.PolicyFields.properties.source.description, /permit or forbid.*context\.now/);
});

for (const [name, mutate] of [
  ["missing-schema", d => { delete d.components.schemas.PolicyFields; }],
  ["missing-response", d => { delete d.components.responses.GroupPage; }],
  ["missing-path", d => { delete d.paths[policies]; }],
  ["group-read-scope", d => { d.paths[groups].get["x-scoplen-required-device-scope"] = "teams:manage"; }],
  ["group-read-actions", d => { d.paths[group].get["x-scoplen-accepted-cedar-actions"].pop(); }],
  ["group-write-scope", d => { d.paths[groups].post["x-scoplen-required-device-scope"] = "policies:write"; }],
  ["group-write-action", d => { d.paths[group].delete["x-scoplen-cedar-action"] = "manage_policy"; }],
  ["policy-read-scope", d => { d.paths[policy].get["x-scoplen-required-device-scope"] = "sync:read"; }],
  ["policy-read-action", d => { d.paths[policies].get["x-scoplen-cedar-action"] = "manage_policy"; }],
  ["policy-write-scope", d => { d.paths[policy].put["x-scoplen-required-device-scope"] = "policies:read"; }],
  ["policy-write-action", d => { d.paths[policies].post["x-scoplen-cedar-action"] = "view_policy"; }],
  ["missing-device", d => { d.paths[group].put.security = []; }],
  ["missing-dpop", d => { delete d.paths[policy].delete.security[0].dpopProof; }],
  ["unknown-fields", d => { d.components.schemas.GroupFields.additionalProperties = true; }],
  ["writable-source", d => { d.components.schemas.GroupFields.properties.source = { type: "string" }; }],
  ["missing-source", d => { delete d.components.schemas.GroupResource.properties.data.properties.source; }],
  ["unknown-origin", d => { d.components.schemas.GroupSource.enum.push("remote"); }],
  ["member-limit", d => { d.components.schemas.GroupFields.properties.members.maxItems++; }],
  ["duplicate-members", d => { d.components.schemas.GroupFields.properties.members.uniqueItems = false; }],
  ["member-uuid", d => { delete d.components.schemas.GroupFields.properties.members.items.pattern; }],
  ["name-bytes", d => { d.components.schemas.GroupFields.properties.name["x-scoplen-max-utf8-bytes"]++; }],
  ["source-bytes", d => { d.components.schemas.PolicyFields.properties.source["x-scoplen-max-utf8-bytes"]++; }],
  ["empty-source", d => { d.components.schemas.PolicyFields.properties.source.minLength = 0; }],
  ["enabled-type", d => { d.components.schemas.PolicyFields.properties.enabled.type = "string"; }],
  ["resource-bound", d => { d.components.schemas.GroupResource["x-scoplen-max-bytes"]++; }],
  ["page-bound", d => { d.components.schemas.PolicyPage["x-scoplen-max-bytes"]++; }],
  ["page-count", d => { d.components.schemas.GroupPage.properties.items.maxItems++; }],
  ["missing-cursor", d => { d.components.schemas.PolicyPage.required.pop(); }],
  ["response-extension", d => { d.components.schemas.PolicyResource.additionalProperties = false; }],
  ["extra-query", d => { d.paths[groups].get.parameters.push({ name: "filter" }); }],
  ["request-budget", d => { d.paths[policies].post["x-scoplen-request-max-bytes"]++; }],
  ["response-budget", d => { d.paths[groups].get["x-scoplen-response-max-bytes"]++; }],
  ["original-key", d => { d.paths[groups].post.parameters[1].required = false; }],
  ["original-tag", d => { d.paths[policy].put.parameters[2].required = false; }],
  ["weak-tag", d => { delete d.paths[group].delete.parameters[2].schema.pattern; }],
  ["required-tag", d => { delete d.paths[group].put.responses["428"]; }],
  ["stale-tag", d => { delete d.paths[policy].delete.responses["412"]; }],
  ["body-too-large", d => { delete d.paths[policies].post.responses["413"]; }],
  ["content-type", d => { delete d.paths[group].put.responses["415"]; }],
  ["rate-limit", d => { delete d.paths[groups].post.responses["429"]; }],
  ["retry-header", d => { delete d.components.responses.GroupPolicyRateLimited.headers["Retry-After"]; }],
  ["resource-etag", d => { delete d.components.responses.GroupResource.headers.ETag; }],
  ["cache", d => { delete d.components.responses.PolicyPage.headers.Pragma; }],
  ["request-id", d => { delete d.paths[policy].delete.responses["204"].headers["X-Request-ID"]; }],
  ["create-unknown-commit", d => { d.paths[groups].post.responses["503"].content["application/problem+json"].schema.oneOf.pop(); }],
  ["replace-unknown-retry", d => { d.paths[policy].put.responses["503"].content["application/problem+json"].schema.oneOf[1].$ref = "#/components/schemas/OrganizationCommitOutcomeUnknownProblem"; }],
  ["delete-unknown-retry", d => { d.paths[group].delete.responses["503"].content["application/problem+json"].schema.oneOf[1].$ref = "#/components/schemas/OrganizationCommitOutcomeUnknownProblem"; }],
  ["patch-instead-of-replace", d => { d.paths[policy].patch = d.paths[policy].put; delete d.paths[policy].put; }],
  ["extra-write-operation", d => { d.paths[group].patch = {}; }],
  ["credential-selector", d => { d.components.schemas.SimpleRuleSelector.properties.type.enum.push(3); }],
  ["float-selector", d => { d.components.schemas.SimpleRuleSelector.properties.type.type = "number"; }],
  ["subject-alternatives", d => { d.components.schemas.SimpleRuleInput.oneOf.pop(); }],
  ["unknown-simple-field", d => { d.components.schemas.SimpleRuleInput.oneOf[0].additionalProperties = true; }],
  ["empty-view", d => { d.components.schemas.SimpleRuleInput.oneOf[0].properties.view.minItems = 0; }],
  ["view-bound", d => { d.components.schemas.SimpleRuleInput.oneOf[2].properties.view.maxItems++; }],
  ["duplicate-selector", d => { d.components.schemas.SimpleRuleInput.oneOf[0].properties.view.uniqueItems = false; }],
  ["empty-connect", d => { delete d.components.schemas.SimpleRuleConnect.anyOf; }],
  ["connect-host-bound", d => { d.components.schemas.SimpleRuleConnect.properties.hosts.maxItems++; }],
  ["connect-group-bound", d => { d.components.schemas.SimpleRuleConnect.properties.host_groups.maxItems++; }],
  ["remote-user-bytes", d => { d.components.schemas.SimpleRuleConnect.properties.remote_user["x-scoplen-max-utf8-bytes"]++; }],
]) test(`D-137 detects ${name} contract drift`, () => {
  const changed = document();
  mutate(changed);
  assert.throws(() => generateGroupPolicyTypes(changed), /D-137/);
});
