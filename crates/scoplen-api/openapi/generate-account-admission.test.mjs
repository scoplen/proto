// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { generateAccountAdmissionTypes } from "./generate-account-admission.mjs";

const document = JSON.parse(readFileSync(new URL("v1.yaml", import.meta.url), "utf8"));

test("D-128 generates explicit submit/confirm and keeps uint64 values as strings", () => {
  const before = JSON.stringify(document), output = generateAccountAdmissionTypes(document);
  assert.equal(JSON.stringify(document), before);
  assert.match(output, /intent: "submit"; admission_token: string/);
  assert.match(output, /intent: "confirm"; admission_token: null/);
  assert.match(output, /admitted_key_revision: string/);
  assert.match(output, /expires_at_ms: string/);
  assert.match(output, /profile: 1/);
  assert.match(output, /export type AccountEntryInvalidRequestProblem = ProblemDetails & /);
  assert.match(output, /code: "auth\.registration_denied"; changed: false; retryable: false/);
  assert.match(output, /code: "auth\.commit_outcome_unknown"; changed: true; retryable: false/);
  assert.match(output, /code: "auth\.storage_unavailable"; changed: false; retryable: true/);
  assert.match(output, /code: "auth\.quota_exceeded"; changed: false; retryable: false/);
  assert.doesNotMatch(output, /access_token|refresh_token|invitation|pairing/);
});

test("D-152 adds one native credential ceremony with its own historical result", () => {
  const output = generateAccountAdmissionTypes(document);
  const schemas = document.components.schemas;
  assert.deepEqual(schemas.AccountRequestChallengeRequest.properties.kind.enum, ["register", "admit", "password_change"]);
  assert.deepEqual(schemas.AccountCommittedConfirmation.properties.kind.enum, ["register", "admit"]);
  assert.equal(schemas.AccountPasswordChangeConfirmation.properties.kind.const, "password_change");
  assert.equal(schemas.AccountPasswordChangeConfirmation.properties.credential_generation.type, "string");
  assert.equal(schemas.AccountPasswordChangeConfirmation.properties.admitted_key_revision, undefined);
  const operation = document.paths["/auth/accounts/password-changes"].post;
  assert.deepEqual(operation.security, []);
  assert.equal(operation["x-scoplen-request-max-bytes"], 16384);
  assert.equal(operation["x-scoplen-response-max-bytes"], 1024);
  assert.equal(schemas.AccountPasswordChangeRequest.properties.payload["x-scoplen-decoded-bytes"].maximum, 8192);
  for (const status of [200, 201]) assert.equal(operation.responses[status].content["application/json"].schema.$ref, "#/components/schemas/AccountPasswordChangeConfirmation");
  assert.equal(operation.responses[409].$ref, "#/components/responses/AccountEntryAdmissionConflict");
  assert.equal(operation.responses[503].$ref, "#/components/responses/AccountEntryStorageFailure");
  assert.match(output, /export type AccountPasswordChangeRequest =\n  \| \(AccountPasswordChangeFields & \{ intent: "submit"; admission_token: string \}\)\n  \| \(AccountPasswordChangeFields & \{ intent: "confirm"; admission_token: null \}\);/);
  assert.match(output, /export interface AccountPasswordChangeConfirmation \{\n  outcome: "committed";\n  kind: "password_change";/);
});

for (const [name, mutate] of [
  ["request extension", d => { d.components.schemas.AccountPasswordOptionsRequest.additionalProperties = true; }],
  ["optional secret", d => { d.components.schemas.AccountPasswordLoginRequest.required.pop(); }],
  ["profile substitution", d => { d.components.schemas.AccountPasswordOptionsResponse.properties.profile.const = 2; }],
  ["numeric uint64", d => { d.components.schemas.AccountCommittedConfirmation.properties.admitted_key_revision.type = "integer"; }],
  ["protected bound", d => { d.components.schemas.AccountRegistrationRequest.properties.payload["x-scoplen-decoded-bytes"].maximum++; }],
  ["lost confirm null", d => { d.components.schemas.AccountDeviceAdmissionRequest.allOf.pop(); }],
  ["login body bound", d => { d.paths["/auth/accounts/password/login"].post["x-scoplen-response-max-bytes"]++; }],
  ["login unknown commit", d => { d.paths["/auth/accounts/password/login"].post.responses[503].$ref = "#/components/responses/AccountEntryStorageFailure"; }],
  ["missing cache prohibition", d => { delete d.paths["/auth/accounts/register"].post.responses[201].headers.Pragma; }],
  ["session authentication", d => { d.paths["/auth/accounts/register"].post.security = [{ accessToken: [] }]; }],
  ["historical receipt creates", d => { d.paths["/auth/accounts/register"].post.description = "Confirm may create when no receipt exists."; }],
  ["changed quota", d => { d.components.responses.AccountEntryTooLarge.content["application/problem+json"].schema.oneOf[1].allOf[1].properties.changed.const = true; }],
  ["lost-commit retry", d => { d.components.responses.AccountEntryStorageFailure.content["application/problem+json"].schema.oneOf[1].allOf[1].properties.retryable.const = true; }],
  ["retired pairing endpoint", d => { d.paths["/auth/pairings"] = { post: {} }; }],
  ["retired Personal endpoint", d => { d.paths["/admin/personal-invitations"] = { post: {} }; }],
  ["password-change challenge kind missing", d => { d.components.schemas.AccountRequestChallengeRequest.properties.kind.enum.pop(); }],
  ["password-change legacy result", d => { d.components.schemas.AccountCommittedConfirmation.properties.kind.enum.push("password_change"); }],
  ["password-change payload overflow", d => { d.components.schemas.AccountPasswordChangeRequest.properties.payload["x-scoplen-decoded-bytes"].maximum++; }],
  ["password-change non-null confirm capability", d => { d.components.schemas.AccountPasswordChangeRequest.allOf.pop(); }],
  ["password-change key revision substitution", d => { const p = d.components.schemas.AccountPasswordChangeConfirmation.properties; p.admitted_key_revision = p.credential_generation; delete p.credential_generation; }],
  ["password-change numeric generation", d => { d.components.schemas.AccountPasswordChangeConfirmation.properties.credential_generation.type = "integer"; }],
  ["password-change body overflow", d => { d.paths["/auth/accounts/password-changes"].post["x-scoplen-request-max-bytes"]++; }],
  ["password-change session authority", d => { d.paths["/auth/accounts/password-changes"].post.security = [{ accessToken: [] }]; }],
]) test(`D-128 rejects ${name}`, () => { const copy = structuredClone(document); mutate(copy); assert.throws(() => generateAccountAdmissionTypes(copy)); });
