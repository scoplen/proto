// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { generateOperatorTypes } from "./generate-operator.mjs";

const document = JSON.parse(readFileSync(new URL("./v1.yaml", import.meta.url), "utf8"));
const logoutPath = "/auth/operator/logout";
const operation = (value) => value.paths[logoutPath].post;
const schema = (value, name) => value.components.schemas[name];
const response = (value, name) => value.components.responses[name];

test("D-124 generates closed logout shapes and distinct retryable commit uncertainty", () => {
  const before = JSON.stringify(document);
  const output = generateOperatorTypes(document);
  assert.equal(JSON.stringify(document), before);
  assert.match(output, /export type OperatorLogoutRequest = Record<string, never>;/);
  assert.match(output, /export interface OperatorLogoutResponse \{\n  revoked: true;\n\}/);
  assert.match(output, /OperatorLogoutAuthenticationRequiredProblem = .*status: 401; code: "auth.authentication_required"; changed: false; retryable: false;/);
  assert.match(output, /OperatorLogoutCommitOutcomeUnknownProblem = .*status: 503; code: "auth.commit_outcome_unknown"; changed: true; retryable: true;/);
  assert.match(output, /export type OperatorLogoutStorageFailureProblem = AuthStorageUnavailableProblem \| OperatorLogoutCommitOutcomeUnknownProblem;/);
});

const regressions = [
  ["caller-selected family", (value) => { schema(value, "OperatorLogoutRequest").properties.sid = { type: "string" }; }],
  ["request extensions", (value) => { schema(value, "OperatorLogoutRequest").additionalProperties = true; }],
  ["confirmation extensions", (value) => { schema(value, "OperatorLogoutResponse").additionalProperties = true; }],
  ["false confirmation", (value) => { schema(value, "OperatorLogoutResponse").properties.revoked.const = false; }],
  ["request size widening", (value) => { operation(value)["x-scoplen-request-max-bytes"] = 257; }],
  ["confirmation size widening", (value) => { operation(value)["x-scoplen-response-max-bytes"] = 257; }],
  ["problem size widening", (value) => { operation(value)["x-scoplen-problem-max-bytes"] = 4097; }],
  ["optional request body", (value) => { operation(value).requestBody.required = false; }],
  ["alternate media type", (value) => { operation(value).requestBody.content["text/plain"] = {}; }],
  ["proof without token", (value) => { operation(value).security = [{ dpopProof: [] }]; }],
  ["token or proof instead of both", (value) => { operation(value).security = [{ accessToken: [] }, { dpopProof: [] }]; }],
  ["missing intrinsic requirement", (value) => { delete operation(value)["x-scoplen-operator-requirement"]; }],
  ["invitation permission", (value) => { operation(value)["x-scoplen-required-operator-scope"] = "personal-invitation:issue"; }],
  ["device permission", (value) => { operation(value)["x-scoplen-required-device-scope"] = "sync:read"; }],
  ["optional Origin", (value) => { operation(value).parameters[0].required = false; }],
  ["cookie parameter", (value) => { operation(value).parameters.push({ name: "refresh", in: "cookie" }); }],
  ["GET alias", (value) => { value.paths[logoutPath].get = structuredClone(operation(value)); }],
  ["intrinsic requirement on another path", (value) => { value.paths["/auth/operator/other"] = { post: structuredClone(operation(value)) }; }],
  ["missing current credential check", (value) => {
    operation(value).description = operation(value).description.replace("active current Operator and authenticating credential", "any historical Operator");
  }],
  ["private quota widening", (value) => {
    operation(value).description = operation(value).description.replace("verified-Operator quota 10 per", "verified-Operator quota 100 per");
  }],
  ["success cookie write", (value) => { operation(value).responses["200"].headers["Set-Cookie"] = { schema: { type: "string" } }; }],
  ["denial cookie write", (value) => { response(value, "OperatorLogoutAuthenticationRequired").headers["set-cookie"] = { schema: { type: "string" } }; }],
  ["cacheable default error", (value) => { response(value, "OperatorProblem").headers["Cache-Control"].schema.const = "public"; }],
  ["generic authentication error", (value) => { operation(value).responses["401"].$ref = "#/components/responses/OperatorAuthenticationRequired"; }],
  ["mutating authentication denial", (value) => { schema(value, "OperatorLogoutAuthenticationRequiredProblem").allOf[1].properties.changed.const = true; }],
  ["nonretryable uncertain commit", (value) => { schema(value, "OperatorLogoutCommitOutcomeUnknownProblem").allOf[1].properties.retryable.const = false; }],
  ["uncertain commit claimed unchanged", (value) => { schema(value, "OperatorLogoutCommitOutcomeUnknownProblem").allOf[1].properties.changed.const = false; }],
  ["native-auth uncertainty reuse", (value) => { schema(value, "OperatorLogoutStorageFailureProblem").oneOf[1].$ref = "#/components/schemas/AuthCommitOutcomeUnknownProblem"; }],
  ["problem base replacement", (value) => { schema(value, "OperatorLogoutAuthenticationRequiredProblem").allOf[0].$ref = "#/components/schemas/OperatorLogoutResponse"; }],
  ["rate quota or label disclosure", (value) => { response(value, "OperatorRateLimited").headers["RateLimit-Policy"].schema.const = '"operator";q=10;w=60'; }],
  ["rollback claimed mutating", (value) => { schema(value, "AuthStorageUnavailableProblem").allOf[1].properties.changed.const = true; }],
];

for (const [name, mutate] of regressions) {
  test("D-124 rejects contract regression: " + name, () => {
    const changed = structuredClone(document);
    mutate(changed);
    assert.throws(() => generateOperatorTypes(changed), /D-111|D-124/);
  });
}
