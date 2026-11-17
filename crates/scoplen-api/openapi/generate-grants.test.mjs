// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { grantDefinitions, generateGrantTypes } from "./generate-grants.mjs";
import { accountBrowserOperations } from "./generate-account-browser.mjs";

const authored = JSON.parse(await readFile(new URL("v1.yaml", import.meta.url), "utf8"));
const collection = "/orgs/{org}/grants", item = `${collection}/{id}`;

test("D-147 replaces generic Grant/PATCH with five strict public operations and typed exports", async () => {
  const output = generateGrantTypes(authored);
  const registry = await readFile(new URL("types.ts", import.meta.url), "utf8");
  const index = await readFile(new URL("index.ts", import.meta.url), "utf8");
  assert.deepEqual(Object.keys(authored.paths).filter(path => path.includes("/grants")), [collection, item]);
  assert.deepEqual(Object.keys(authored.paths[collection]), ["get", "post"]);
  assert.deepEqual(Object.keys(authored.paths[item]), ["get", "put", "delete"]);
  assert.equal(authored.components.schemas.Grant, undefined);
  assert.doesNotMatch(registry, /Grant: Resource;/);
  for (const name of [...Object.keys(grantDefinitions().schemas), "GrantListQuery"]) {
    assert.match(index, new RegExp(`^  ${name},$`, "m"));
    if (name !== "GrantListQuery") assert.match(registry, new RegExp(`^    ${name}: ${name};$`, "m"));
  }
  assert.match(output, /valid_from: string; valid_until: string \| null;/);
  assert.match(output, /data: GrantFields & \{ \[extension: string\]: unknown \}/);
});

test("D-147 preserves exact writable fields, explicit nullable expiry and complete encoded bounds", () => {
  const { schemas, paths } = grantDefinitions();
  const expected = ["membership", "host", "remote_user", "valid_from", "valid_until"];
  assert.deepEqual(schemas.GrantFields.required, expected);
  assert.deepEqual(Object.keys(schemas.GrantFields.properties), expected);
  assert.deepEqual(schemas.GrantResource.properties.data.required, expected);
  for (const name of ["GrantFields", "GrantCreateRequest", "GrantReplaceRequest"]) assert.equal(schemas[name].additionalProperties, false);
  assert.equal(schemas.GrantResource.additionalProperties, true);
  assert.equal(schemas.GrantResource.properties.data.additionalProperties, true);
  assert.equal(schemas.GrantPage.additionalProperties, true);
  for (const name of ["GrantCreateRequest", "GrantReplaceRequest", "GrantResource"]) assert.equal(schemas[name]["x-scoplen-max-bytes"], 4096);
  assert.equal(schemas.GrantPage["x-scoplen-max-bytes"], 2097152);
  assert.equal(schemas.GrantPage.properties.items.maxItems, 500);
  assert.equal(schemas.GrantFields.properties.remote_user["x-scoplen-max-utf8-bytes"], 255);
  const time = schemas.GrantFields.properties.valid_from;
  const pattern = new RegExp(time.pattern);
  for (const text of ["1970-01-01T00:00:00Z", "9999-12-31T23:59:59Z"]) assert.ok(pattern.test(text));
  for (const text of ["2026-11-17T00:00:00.1Z", "2026-11-17T00:00:00+00:00", "2026-11-17T24:00:00Z", "2026-11-17T00:00:60Z"]) assert.ok(!pattern.test(text));
  assert.deepEqual(schemas.GrantFields.properties.valid_until.anyOf[1], { type: "null" });
  assert.match(schemas.GrantFields.properties.valid_until.description, /strictly later/);
  assert.match(time.description, /0\.\.253402300799/);
  assert.deepEqual(paths[collection].get.parameters.map(p => p.name), ["org", "limit", "cursor"]);
  assert.deepEqual(paths[collection].get.parameters[1].schema, { type: "integer", minimum: 1, maximum: 500, default: 50 });
  assert.deepEqual(paths[collection].post.parameters.map(p => p.name), ["org", "Idempotency-Key"]);
  for (const method of ["put", "delete"]) assert.deepEqual(paths[item][method].parameters.map(p => p.name), ["org", "id", "If-Match"]);
});

test("D-147 independently registers Device/browser policy scopes and original writer semantics", () => {
  const { paths } = grantDefinitions();
  const operations = accountBrowserOperations().filter(operation => operation.path.includes("/grants"));
  assert.equal(operations.length, 5);
  for (const [path, methods] of Object.entries(paths)) for (const [method, operation] of Object.entries(methods)) {
    const scope = method === "get" ? "policies:read" : "policies:write";
    assert.equal(operation["x-scoplen-required-device-scope"], scope);
    assert.equal(operation["x-scoplen-required-browser-scope"], scope);
    assert.equal(operation["x-scoplen-cedar-action"], method === "get" ? "view_policy" : "manage_policy");
    assert.deepEqual(operation.security, [{ accessToken: [], dpopProof: [] }, { accountBrowserAccess: [], dpopProof: [] }]);
    assert.equal(operation["x-scoplen-fetch-credentials"], "omit");
    assert.equal(operation["x-scoplen-problem-max-bytes"], 4096);
    const browser = operations.find(o => o.method === method.toUpperCase() && o.path === `/api/v1${path}`);
    assert.deepEqual(browser?.scopes, [scope]);
    assert.equal(browser?.writerReceipt, method === "post");
  }
  assert.match(paths[collection].post.description, /immutable original bytes/);
  assert.match(paths[collection].post.description, /After current management authority, look up the exact original receipt before validating live referenced Membership\/Host/);
  assert.match(paths[collection].post.description, /confirmation may succeed after Grant withdrawal, Membership change or Host deletion/);
  assert.match(grantDefinitions().schemas.GrantResource.description, /including future and expired intervals, prevent referenced Host deletion/);
  assert.match(grantDefinitions().schemas.GrantFields.description, /cannot gain a HostGroup principal/);
  assert.match(paths[item].put.description, /no-op without revision or audit/);
  assert.match(paths[item].delete.description, /private marker/);
  assert.match(paths[item].put.responses["503"].description, /refresh and review/);
  assert.equal(paths[item].delete.responses["204"].content, undefined);
});

test("D-147 generation rejects field, endpoint, principal, precondition and bound drift", () => {
  for (const mutate of [
    d => { d.components.schemas.Grant = {}; },
    d => { delete d.components.schemas.GrantFields; },
    d => { d.components.schemas.GrantFields.required.pop(); },
    d => { d.components.schemas.GrantFields.additionalProperties = true; },
    d => { d.components.schemas.GrantFields.properties.account = { type: "string" }; },
    d => { d.components.schemas.GrantFields.properties.valid_until.anyOf.pop(); },
    d => { d.components.schemas.GrantResource["x-scoplen-max-bytes"]++; },
    d => { d.components.schemas.GrantPage["x-scoplen-max-bytes"]++; },
    d => { d.components.schemas.GrantPage.properties.items.maxItems++; },
    d => { d.paths[item].patch = d.paths[item].put; delete d.paths[item].put; },
    d => { d.paths[`${collection}/evaluate`] = { post: {} }; },
    d => { d.paths[collection].get.parameters.push({ name: "filter" }); },
    d => { d.paths[collection].post.parameters[1].required = false; },
    d => { d.paths[item].put.parameters.pop(); },
    d => { d.paths[item].delete.responses["428"] = {}; },
    d => { d.paths[item].get["x-scoplen-required-device-scope"] = "inventory:read"; },
    d => { d.paths[item].put["x-scoplen-required-browser-scope"] = "teams:manage"; },
    d => { d.paths[item].put.security.pop(); },
    d => { d.paths[collection].post["x-scoplen-request-max-bytes"]++; },
    d => { d.paths[collection].get["x-scoplen-response-max-bytes"]++; },
    d => { delete d.components.responses.GrantResource.headers.ETag; },
  ]) { const copy = structuredClone(authored); mutate(copy); assert.throws(() => generateGrantTypes(copy), /D-147/); }
});
