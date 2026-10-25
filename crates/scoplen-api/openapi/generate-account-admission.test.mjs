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
]) test(`D-128 rejects ${name}`, () => { const copy = structuredClone(document); mutate(copy); assert.throws(() => generateAccountAdmissionTypes(copy)); });
