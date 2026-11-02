// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import test from "node:test";
import { generateUserCaTypes, userCaDefinitions } from "./generate-user-ca.mjs";

const collection = "/orgs/{org}/certificate-authorities";
const individual = `${collection}/{id}`;
const fixture = () => {
  const { schemas, responses, paths } = userCaDefinitions();
  return structuredClone({ components: { schemas, responses }, paths });
};

test("D-137 freezes only three initial local-user-CA operations and precise public metadata", () => {
  const document = fixture();
  const types = generateUserCaTypes(document);
  assert.deepEqual(Object.keys(document.paths), [collection, individual]);
  assert.deepEqual(Object.keys(document.paths[collection]), ["get", "post"]);
  assert.deepEqual(Object.keys(document.paths[individual]), ["get"]);
  assert.equal(document.paths[collection].post["x-scoplen-required-device-scope"], "ca:write");
  assert.equal(document.paths[collection].post["x-scoplen-cedar-action"], "manage_ca");
  assert.equal(document.paths[collection].get["x-scoplen-required-device-scope"], "ca:read");
  assert.equal(document.paths[individual].get["x-scoplen-required-device-scope"], "ca:read");
  assert.deepEqual(document.components.schemas.UserCaCreateRequest.required, ["id", "data"]);
  assert.deepEqual(document.components.schemas.UserCaCreateRequest.properties.data.required, ["kind", "backend"]);
  assert.equal(document.components.schemas.UserCaCreateRequest.additionalProperties, false);
  assert.equal(document.components.schemas.UserCaCreateRequest.properties.data.additionalProperties, false);
  assert.equal(document.components.schemas.UserCaResource.additionalProperties, true);
  assert.equal(document.components.schemas.UserCaResource.properties.data.additionalProperties, true);
  assert.equal(document.components.schemas.UserCaResource["x-scoplen-max-bytes"], 16384);
  assert.equal(document.components.schemas.UserCaPage["x-scoplen-max-bytes"], 1048576);
  assert.equal(document.components.schemas.UserCaPage.properties.items.maxItems, 500);
  for (const name of ["UserCaCreateRequest", "UserCaResource", "UserCaPage"]) assert.match(types, new RegExp(`interface ${name}`));
  assert.match(types, /kind: "user"; backend: "local"; state: "active"/);
  assert.doesNotMatch(types, /private_key|seed:|organization_id:/);
  assert.deepEqual(document.paths[collection].post.security, [{ accessToken: [], dpopProof: [] }]);
});

for (const [name, mutate] of [
  ["create-id-optional", d => { d.components.schemas.UserCaCreateRequest.required.shift(); }],
  ["request-extension", d => { d.components.schemas.UserCaCreateRequest.properties.data.additionalProperties = true; }],
  ["host-kind", d => { d.components.schemas.UserCaResource.properties.data.properties.kind.const = "host"; }],
  ["remote-backend", d => { d.components.schemas.UserCaCreateRequest.properties.data.properties.backend.const = "aws_kms"; }],
  ["rotation-state", d => { d.components.schemas.UserCaResource.properties.data.properties.state.const = "next"; }],
  ["fingerprint-format", d => { d.components.schemas.UserCaResource.properties.data.properties.fingerprint.pattern = ".*"; }],
  ["key-algorithm", d => { d.components.schemas.UserCaResource.properties.data.properties.public_key.pattern = ".*"; }],
  ["resource-bound", d => { d.components.schemas.UserCaResource["x-scoplen-max-bytes"]++; }],
  ["page-bound", d => { d.components.schemas.UserCaPage["x-scoplen-max-bytes"]++; }],
  ["item-bound", d => { d.components.schemas.UserCaPage.properties.items["x-scoplen-max-item-bytes"]++; }],
  ["page-count", d => { d.components.schemas.UserCaPage.properties.items.maxItems++; }],
  ["missing-continuation", d => { d.components.schemas.UserCaPage.required.pop(); }],
  ["create-scope", d => { d.paths[collection].post["x-scoplen-required-device-scope"] = "certificates:issue"; }],
  ["read-scope", d => { d.paths[individual].get["x-scoplen-required-device-scope"] = "sync:read"; }],
  ["write-policy", d => { d.paths[collection].post["x-scoplen-cedar-action"] = "view_inventory"; }],
  ["body-bound", d => { d.paths[collection].post["x-scoplen-request-max-bytes"]++; }],
  ["idempotency-optional", d => { d.paths[collection].post.parameters[1].required = false; }],
  ["nonce-security", d => { delete d.paths[collection].post.security[0].dpopProof; }],
  ["query-extension", d => { d.paths[collection].get.parameters.push({ name: "kind", in: "query" }); }],
  ["read-body", d => { d.paths[individual].get.requestBody = {}; }],
  ["read-cache", d => { delete d.paths[collection].get.responses["200"].headers.Pragma; }],
  ["read-etag", d => { delete d.paths[individual].get.responses["200"].headers.ETag; }],
  ["create-unknown-commit", d => { d.paths[collection].post.responses["503"].content["application/problem+json"].schema.oneOf.pop(); }],
  ["generic-patch", d => { d.paths[individual].patch = {}; }],
  ["generic-delete", d => { d.paths[individual].delete = {}; }],
]) test(`D-137 detects user-CA ${name} drift`, () => {
  const document = fixture(); mutate(document);
  assert.throws(() => generateUserCaTypes(document), /D-137 user-CA/);
});

test("D-137 fingerprint schema uses unpadded standard Base64 and exact 32-byte digest shape", () => {
  const pattern = new RegExp(fixture().components.schemas.UserCaResource.properties.data.properties.fingerprint.pattern);
  const good = "SHA256:bbXpuKG6zhzdmnxq256TlqzFBzRl2f6OOg722cYNbU8";
  assert.ok(pattern.test(good));
  for (const invalid of [good + "=", good + " comment", good.slice(0, -1) + "9", good.replace("SHA256:", "sha256:"), "SHA256:" + "A".repeat(42), "SHA256:" + "_".repeat(43)]) assert.ok(!pattern.test(invalid));
});
