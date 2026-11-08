// SPDX-License-Identifier: Apache-2.0
import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { generateUserCaTypes, userCaDefinitions } from "./generate-user-ca.mjs";

const document = JSON.parse(await readFile(new URL("v1.yaml", import.meta.url), "utf8"));

test("authored user-CA contracts are exported through the public package", async () => {
  const generated = generateUserCaTypes(document);
  const index = await readFile(new URL("index.ts", import.meta.url), "utf8");
  const types = (await readFile(new URL("types.ts", import.meta.url), "utf8")).replaceAll("\r\n", "\n");
  for (const name of Object.keys(userCaDefinitions().schemas)) {
    assert.match(index, new RegExp(`^  ${name},$`, "m"));
    assert.match(types, new RegExp(`^    ${name}: ${name};$`, "m"));
  }
  assert.ok(types.includes(generated));
  assert.equal(document.components.schemas.CertificateAuthority, undefined);
  assert.doesNotMatch(types, /^    CertificateAuthority: Resource;$/m);
});

test("issuance preserves D-88 and D-90 with current authority and original receipt recovery", () => {
  const issue = document.paths["/orgs/{org}/certificates"].post;
  assert.equal(issue["x-scoplen-required-device-scope"], "certificates:issue");
  assert.deepEqual(issue.security, [{ accessToken: [], dpopProof: [] }]);
  assert.equal(issue["x-scoplen-request-max-bytes"], 16384);
  assert.equal(issue["x-scoplen-response-max-bytes"], 131072);
  assert.deepEqual(issue.parameters, [
    { $ref: "#/components/parameters/org" },
    { name: "Idempotency-Key", in: "header", required: true, schema: userCaDefinitions().schemas.UserCaCreateRequest.properties.id },
  ]);
  assert.equal(issue.requestBody.content["application/json"].schema.$ref, "#/components/schemas/CertificateRequest");
  assert.equal(issue.responses["201"].content["application/json"].schema.$ref, "#/components/schemas/CertificateIssuanceResponse");
  assert.equal(issue.responses["201"].headers["X-Request-ID"].required, true);
  assert.equal(issue.responses["400"].$ref, "#/components/responses/Problem");
  assert.equal(issue.responses["409"].$ref, "#/components/responses/CertificateConflict");
  assert.equal(issue.responses["413"].$ref, "#/components/responses/CertificateTooLarge");
  assert.deepEqual(issue.responses["503"].content["application/problem+json"].schema.oneOf, [
    { $ref: "#/components/schemas/OrganizationStorageUnavailableProblem" },
    { $ref: "#/components/schemas/OrganizationCommitOutcomeUnknownProblem" },
  ]);
  assert.match(issue.description, /every current group Host/);
  assert.match(issue.description, /route_kind="direct"/);
  assert.match(issue.description, /rechecks current membership and all target authority/);
  assert.match(issue.description, /without a new serial or extended expiry/);
  assert.match(issue.responses["503"].description, /changed=true\/retryable=true/);
});

test("authored OpenAPI references resolve after retiring the generic CA schema", () => {
  const visit = value => {
    if (!value || typeof value !== "object") return;
    if (typeof value.$ref === "string" && value.$ref.startsWith("#/")) {
      const target = value.$ref.slice(2).split("/").reduce((node, key) => node?.[key.replaceAll("~1", "/").replaceAll("~0", "~")], document);
      assert.notEqual(target, undefined, value.$ref);
    }
    for (const child of Object.values(value)) visit(child);
  };
  visit(document);
});
