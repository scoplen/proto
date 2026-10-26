// SPDX-License-Identifier: Apache-2.0
import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { generateOrganizationTypes } from "./generate-organizations.mjs";
const document = JSON.parse(await readFile(new URL("v1.yaml", import.meta.url), "utf8"));
test("D-130 authored contract generates caller-specific types", () => {
  const types = generateOrganizationTypes(document);
  for (const name of ["OrganizationCreateRequest", "OrganizationResource", "OrganizationMembership", "OrganizationPage"]) assert.match(types, new RegExp(`interface ${name}`));
  assert.match(types, /roles: string\[\]/);
});
for (const [name, mutate] of [
  ["create-scope", d => { d.paths["/orgs"].post["x-scoplen-required-device-scope"] = "account:read"; }],
  ["read-scope", d => { d.paths["/orgs/{org}"].get["x-scoplen-required-device-scope"] = "sync:read"; }],
  ["request-bound", d => { d.paths["/orgs"].post["x-scoplen-request-max-bytes"]++; }],
  ["optional-key", d => { d.paths["/orgs"].post.parameters[0].required = false; }],
  ["extra-query", d => { d.paths["/orgs"].get.parameters.push({ name: "filter" }); }],
  ["missing-account", d => { d.components.schemas.OrganizationMembership.required.splice(1, 1); }],
  ["unknown-request", d => { d.components.schemas.OrganizationCreateRequest.additionalProperties = true; }],
  ["role-bound", d => { d.components.schemas.OrganizationMembership.properties.roles.maxItems++; }],
  ["page-bound", d => { d.components.schemas.OrganizationPage["x-scoplen-max-bytes"]++; }],
  ["cache", d => { delete d.paths["/orgs"].get.responses["200"].headers.Pragma; }],
  ["etag", d => { delete d.paths["/orgs/{org}"].get.responses["200"].headers.ETag; }],
  ["unknown-retry", d => { d.components.schemas.OrganizationCommitOutcomeUnknownProblem.allOf[1].properties.retryable.const = false; }],
]) test(`D-130 detects ${name} drift`, () => { const changed = structuredClone(document); mutate(changed); assert.throws(() => generateOrganizationTypes(changed), /D-130/); });
