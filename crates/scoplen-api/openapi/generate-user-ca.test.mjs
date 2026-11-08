// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import test from "node:test";
import { generateUserCaTypes, userCaDefinitions } from "./generate-user-ca.mjs";

const collection = "/orgs/{org}/certificate-authorities";
const individual = `${collection}/{id}`;
const krl = `${individual}/krl`;
const fixture = () => {
  const { schemas, responses, paths } = userCaDefinitions();
  return structuredClone({ components: { schemas, responses }, paths });
};

test("D-137/D-141 freeze initial local-user-CA metadata and revocation reads", () => {
  const document = fixture();
  const types = generateUserCaTypes(document);
  assert.deepEqual(Object.keys(document.paths), [collection, individual, krl]);
  assert.deepEqual(Object.keys(document.paths[collection]), ["get", "post"]);
  assert.deepEqual(Object.keys(document.paths[individual]), ["get"]);
  assert.deepEqual(Object.keys(document.paths[krl]), ["get"]);
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

test("D-141 KRL read is binary and current-member scoped without browser or admin substitution", () => {
  const document = fixture();
  const operation = document.paths[krl].get;
  assert.equal(operation["x-scoplen-required-device-scope"], "ca:read");
  assert.equal(operation["x-scoplen-cedar-action"], undefined);
  assert.deepEqual(operation.security, [{ accessToken: [], dpopProof: [] }]);
  assert.equal(operation["x-scoplen-response-max-bytes"], 4194304);
  assert.equal(operation.requestBody, undefined);
  assert.deepEqual(operation.parameters.map(p => p.name), ["org", "id"]);
  const success = operation.responses["200"];
  assert.deepEqual(Object.keys(success.content), ["application/octet-stream"]);
  assert.equal(success.content["application/octet-stream"].schema.$ref, "#/components/schemas/UserCaKrl");
  assert.equal(success.headers.ETag, undefined);
  assert.equal(success.headers["Cache-Control"].schema.const, "no-store");
  assert.equal(success.headers.Pragma.schema.const, "no-cache");
  assert.equal(success.headers["X-Request-ID"].required, true);
  assert.equal(operation.responses["304"], undefined);
  assert.equal(operation.responses["206"], undefined);
  assert.match(operation.description, /dissolved Organization/);
  assert.match(operation.description, /never an empty KRL/);
  assert.match(generateUserCaTypes(document), /UserCaKrl = Uint8Array/);
});

test("D-141 exact terminal problems distinguish historical revocation and quota from syntax", () => {
  const { schemas, responses } = userCaDefinitions();
  for (const [name, status, code] of [
    ["CertificateRevokedProblem", 409, "certificate.revoked"],
    ["CertificateQuotaExceededProblem", 413, "certificate.quota_exceeded"],
    ["CertificateBodyTooLargeProblem", 413, "certificate.invalid_request"],
  ]) {
    assert.deepEqual(schemas[name].allOf[1].properties, {
      status: { const: status }, code: { const: code }, changed: { const: false }, retryable: { const: false },
    });
  }
  assert.deepEqual(responses.CertificateTooLarge.content["application/problem+json"].schema.oneOf, [
    { $ref: "#/components/schemas/CertificateBodyTooLargeProblem" },
    { $ref: "#/components/schemas/CertificateQuotaExceededProblem" },
  ]);
  assert.deepEqual(responses.CertificateConflict.content["application/problem+json"].schema.oneOf, [
    { $ref: "#/components/schemas/OrganizationConflictProblem" },
    { $ref: "#/components/schemas/CertificateRevokedProblem" },
  ]);
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
  ["krl-scope", d => { d.paths[krl].get["x-scoplen-required-device-scope"] = "ca:write"; }],
  ["krl-body", d => { d.paths[krl].get.requestBody = {}; }],
  ["krl-bound", d => { d.paths[krl].get["x-scoplen-response-max-bytes"]++; }],
  ["krl-json", d => { d.paths[krl].get.responses["200"].content = { "application/json": {} }; }],
  ["krl-cache", d => { delete d.paths[krl].get.responses["200"].headers.Pragma; }],
  ["krl-absence", d => { d.paths[krl].get.responses["503"].content["application/problem+json"].schema = { type: "null" }; }],
  ["revoked-retry", d => { d.components.schemas.CertificateRevokedProblem.allOf[1].properties.retryable.const = true; }],
  ["quota-status", d => { d.components.schemas.CertificateQuotaExceededProblem.allOf[1].properties.status.const = 429; }],
  ["quota-syntax", d => { d.components.responses.CertificateTooLarge.content["application/problem+json"].schema.oneOf.shift(); }],
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
