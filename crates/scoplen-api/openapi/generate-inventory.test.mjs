// SPDX-License-Identifier: Apache-2.0
import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { inventoryDefinitions, generateInventoryTypes } from "./generate-inventory.mjs";

const document = JSON.parse(await readFile(new URL("v1.yaml", import.meta.url), "utf8"));
const kinds = [
  ["Host", "hosts", 1], ["AccessProfile", "access-profiles", 2], ["Route", "routes", 4],
  ["HostGroup", "host-groups", 5], ["TrustRecord", "trust-records", 6],
  ["Snippet", "snippets", 7], ["GatewayNetwork", "gateway-networks", 11],
];

test("D-137 authored inventory generates seven concrete public contracts", () => {
  const types = generateInventoryTypes(document);
  assert.equal(Object.keys(inventoryDefinitions().paths).length, 14);
  for (const [name, segment, type] of kinds) {
    const prefix = `Inventory${name}`;
    for (const suffix of ["Fields", "ReadFields", "CreateRequest", "ReplaceRequest", "Resource", "Page"]) {
      assert.match(types, new RegExp(`(?:type|interface) ${prefix}${suffix}\\b`));
    }
    assert.equal(document.components.schemas[`${prefix}Fields`]["x-scoplen-k1-type"], type);
    assert.deepEqual(Object.keys(document.paths[`/orgs/{org}/${segment}`]), ["get", "post"]);
    assert.deepEqual(Object.keys(document.paths[`/orgs/{org}/${segment}/{id}`]), ["get", "put", "delete"]);
  }
});

test("D-137 no Organization credentials, field clocks or generic opaque fields", () => {
  const schemas = document.components.schemas;
  for (const name of ["Host", "AccessProfile", "HostGroup", "TrustRecord", "Snippet", "GatewayNetwork"]) {
    assert.equal(schemas[`Inventory${name}Fields`].additionalProperties, false);
  }
  assert.equal(schemas.InventoryAccessProfileFields.properties.credential, undefined);
  assert.equal(schemas.InventoryAccessProfileFields.properties.forwards, undefined);
  for (const variant of schemas.InventoryRouteFields.oneOf) {
    assert.equal(variant.additionalProperties, false);
    assert.equal(variant.properties.proxy_credential, undefined);
    assert.equal(variant.properties.proxy_username, undefined);
  }
  assert.deepEqual(schemas.InventoryHostGroupFields.properties.defaults.propertyNames.not, { const: "credential" });
  for (const [name] of kinds) {
    const schema = schemas[`Inventory${name}CreateRequest`];
    assert.equal(schema.additionalProperties, false);
    assert.deepEqual(schema.properties.data.required, ["fields"]);
    assert.equal(schema.properties.data.additionalProperties, false);
  }
});

test("D-137 attribution stays server-owned and secret variables have no default", () => {
  const schemas = document.components.schemas;
  for (const name of ["accepted_at", "accepted_by_device", "accepted_by_account"]) {
    assert.equal(schemas.InventoryTrustRecordFields.properties[name], undefined);
    assert.ok(schemas.InventoryTrustRecordReadFields.required.includes(name));
    assert.equal(schemas.InventoryTrustRecordReadFields.properties[name].readOnly, true);
  }
  assert.deepEqual(schemas.InventorySnippetVariable.oneOf[3].required, ["kind"]);
  assert.deepEqual(Object.keys(schemas.InventorySnippetVariable.oneOf[3].properties), ["kind"]);
  assert.equal(schemas.InventorySnippetVariable.oneOf[1].properties.default.type, "string");
  assert.equal(schemas.InventoryTrustRecordReadFields.properties.accepted_at.type, "string");
});

test("D-137 concrete schemas are available through public package exports", async () => {
  const index = await readFile(new URL("index.ts", import.meta.url), "utf8");
  const types = await readFile(new URL("types.ts", import.meta.url), "utf8");
  const registry = types.slice(types.indexOf("export interface components"), types.indexOf("export interface Resource"));
  for (const name of Object.keys(inventoryDefinitions().schemas)) {
    assert.match(index, new RegExp(`^  ${name},$`, "m"));
    assert.match(registry, new RegExp(`^    ${name}: ${name};$`, "m"));
  }
  assert.doesNotMatch(registry, /^    (Host|AccessProfile|Route|HostGroup|TrustRecord|Snippet|GatewayNetwork): Resource;$/m);
});

for (const [name, segment] of kinds) {
  test(`D-137 ${name} authority, budgets and exact mutation methods`, () => {
    const collection = document.paths[`/orgs/{org}/${segment}`];
    const individual = document.paths[`/orgs/{org}/${segment}/{id}`];
    for (const operation of [collection.get, individual.get]) {
      assert.equal(operation["x-scoplen-required-device-scope"], "inventory:read");
      assert.equal(operation["x-scoplen-cedar-action"], "view_inventory");
      assert.equal(operation.requestBody, undefined);
    }
    for (const operation of [collection.post, individual.put, individual.delete]) {
      assert.equal(operation["x-scoplen-required-device-scope"], "inventory:write");
      assert.equal(operation["x-scoplen-cedar-action"], "manage_inventory");
      assert.deepEqual(operation.security, [{ accessToken: [], dpopProof: [] }]);
    }
    assert.equal(collection.get["x-scoplen-response-max-bytes"], 8388608);
    assert.equal(individual.get["x-scoplen-response-max-bytes"], 2097152);
    assert.equal(collection.post["x-scoplen-request-max-bytes"], 2097152);
    assert.equal(individual.put["x-scoplen-request-max-bytes"], 2097152);
    assert.deepEqual(collection.post.parameters.map(p => p.name), ["org", "Idempotency-Key"]);
    for (const operation of [individual.put, individual.delete]) {
      assert.deepEqual(operation.parameters.map(p => p.name), ["org", "id", "If-Match"]);
      assert.ok(operation.responses["412"]);
      assert.ok(operation.responses["428"]);
    }
    assert.equal(individual.delete.responses["204"].content, undefined);
    assert.equal(individual.delete.requestBody, undefined);
    assert.match(collection.post.responses["503"].description, /changed=true\/retryable=true/);
    assert.match(individual.put.responses["503"].description, /changed=true\/retryable=false/);
  });
}

for (const [name, mutate] of [
  ["request-extensions", d => { d.components.schemas.InventoryHostCreateRequest.additionalProperties = true; }],
  ["field-extensions", d => { d.components.schemas.InventoryHostFields.additionalProperties = true; }],
  ["required-address", d => { d.components.schemas.InventoryHostFields.required.pop(); }],
  ["integer-token", d => { delete d.components.schemas.InventoryHostFields.properties.port["x-scoplen-integer-token"]; }],
  ["direct-route", d => { d.components.schemas.InventoryAccessProfileFields.properties.route.oneOf[1].const = "0"; }],
  ["server-attribution", d => { d.components.schemas.InventoryTrustRecordFields.properties.accepted_at = { type: "string" }; }],
  ["secret-default", d => { d.components.schemas.InventorySnippetVariable.oneOf[3].properties.default = { type: "string" }; }],
  ["request-budget", d => { d.paths["/orgs/{org}/hosts"].post["x-scoplen-request-max-bytes"]++; }],
  ["page-budget", d => { d.components.schemas.InventoryHostPage["x-scoplen-max-bytes"]++; }],
  ["k1-budget", d => { d.components.schemas.InventoryRouteFields["x-scoplen-k1-max-bytes"]++; }],
  ["scope", d => { d.paths["/orgs/{org}/hosts"].get["x-scoplen-required-device-scope"] = "sync:read"; }],
  ["policy", d => { d.paths["/orgs/{org}/hosts/{id}"].put["x-scoplen-cedar-action"] = "view_inventory"; }],
  ["method", d => { d.paths["/orgs/{org}/hosts/{id}"].patch = d.paths["/orgs/{org}/hosts/{id}"].put; }],
  ["etag", d => { d.paths["/orgs/{org}/hosts/{id}"].put.parameters[2].required = false; }],
  ["cache", d => { delete d.paths["/orgs/{org}/hosts/{id}"].get.responses["200"].headers.Pragma; }],
  ["request-id", d => { delete d.paths["/orgs/{org}/hosts"].get.responses["200"].headers["X-Request-ID"]; }],
]) test(`D-137 detects inventory ${name} drift`, () => {
  const changed = structuredClone(document);
  mutate(changed);
  assert.throws(() => generateInventoryTypes(changed), /D-137 inventory/);
});
