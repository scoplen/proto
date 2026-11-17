// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { generateInventoryImportTypes, inventoryImportDefinitions } from "./generate-inventory-import.mjs";
const document = JSON.parse(await readFile(new URL("v1.yaml", import.meta.url), "utf8"));

test("D-151 replaces job CRUD with one exact typed atomic operation", async () => {
  const types = generateInventoryImportTypes(document);
  assert.deepEqual(Object.keys(document.paths["/orgs/{org}/inventory/imports"]), ["post"]);
  assert.equal(document.paths["/orgs/{org}/inventory/imports/{id}"], undefined);
  assert.equal(document.components.schemas.InventoryImport, undefined);
  const operation = document.paths["/orgs/{org}/inventory/imports"].post;
  assert.equal(operation["x-scoplen-required-device-scope"], "inventory:write");
  assert.equal(operation["x-scoplen-cedar-action"], "manage_inventory");
  assert.equal(operation["x-scoplen-request-max-bytes"], 2097152);
  assert.equal(operation["x-scoplen-response-max-bytes"], 32768);
  assert.deepEqual(operation.parameters.map(value => value.name), ["org", "Idempotency-Key"]);
  assert.equal(operation.responses[201].headers.Location, undefined);
  const index = await readFile(new URL("index.ts", import.meta.url), "utf8");
  const generated = await readFile(new URL("types.ts", import.meta.url), "utf8");
  for (const name of Object.keys(inventoryImportDefinitions().schemas)) {
    assert.match(types, new RegExp(`interface ${name}\\b`));
    assert.match(index, new RegExp(`^  ${name},$`, "m"));
    assert.match(generated, new RegExp(`^    ${name}: ${name};$`, "m"));
  }
});
test("D-151 schema rejects nulls and preserves only optional login_name", () => {
  const { schemas } = inventoryImportDefinitions();
  assert.deepEqual(schemas.InventoryImportRow.required, ["host_id", "access_profile_id", "name", "address", "port", "username"]);
  assert.equal(schemas.InventoryImportRow.additionalProperties, false);
  assert.equal(schemas.InventoryImportRow.properties.port["x-scoplen-integer-token"], true);
  assert.equal(schemas.InventoryImportPair.additionalProperties, true);
  for (const change of [
    d => d.paths["/orgs/{org}/inventory/imports"].get = {},
    d => d.paths["/orgs/{org}/inventory/imports/{id}"] = {},
    d => d.components.schemas.InventoryImport = {},
    d => d.components.schemas.InventoryImportRow.required.push("login_name"),
    d => d.components.schemas.InventoryImportRow.properties.port["x-scoplen-integer-token"] = false,
  ]) { const copy = structuredClone(document); change(copy); assert.throws(() => generateInventoryImportTypes(copy), /D-151/); }
});
