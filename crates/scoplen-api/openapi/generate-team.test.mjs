// SPDX-License-Identifier: Apache-2.0
import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { generateTeamTypes, teamDefinitions } from "./generate-team.mjs";

const document = JSON.parse(await readFile(new URL("v1.yaml", import.meta.url), "utf8"));
const invitation = "/orgs/{org}/invitations";
const preview = `${invitation}/{invitation}`;
const accept = `${preview}/accept`;
const members = "/orgs/{org}/members";
const member = `${members}/{membership}`;
const dissolve = "/orgs/{org}/dissolve";

test("D-136 generates exact named-Account invitation, membership and historical receipt types", () => {
  const types = generateTeamTypes(document);
  for (const name of ["TeamInvitationCreateRequest", "TeamInvitationAcceptRequest", "TeamInvitationResource", "TeamInvitationPage", "TeamMemberUpdateRequest", "TeamMemberResource", "TeamMemberPage", "TeamAcceptanceReceipt", "TeamDissolveRequest", "TeamDissolutionReceipt"]) assert.match(types, new RegExp(`interface ${name}`));
  assert.match(types, /roles: TeamRole\[\]/);
  assert.match(types, /status: "accepted"; membership_id: string/);
  assert.match(types, /membership_id: null/);
  assert.match(types, /TeamInvitationDeniedProblem.*status: 409; code: "organization.invitation_denied"; changed: false; retryable: false/);
  assert.equal(Object.keys(teamDefinitions().paths).length, 6);
  assert.equal(Object.values(teamDefinitions().paths).flatMap(path => Object.keys(path)).length, 10);
  assert.ok(!Object.hasOwn(document.paths[members], "post"));
});

test("D-136 password and verifier schema patterns preserve the exact shared byte profiles", () => {
  const password = new RegExp(document.components.schemas.TeamInvitationAcceptRequest.properties.password.pattern);
  for (const text of ["01234567", "ABCDEFGH", "JKMNPQRS", "TVWXYZ01"]) assert.ok(password.test(text));
  for (const text of ["0123456", "012345678", "abcdefg0", "I1234567", "L1234567", "O1234567", "U1234567", "0123456\n", " 1234567", "012345é"]) assert.ok(!password.test(text));
  const verifier = new RegExp(document.components.schemas.TeamInvitationCreateRequest.properties.password_verifier.pattern);
  for (const byte of [0, 1, 127, 255]) assert.ok(verifier.test(Buffer.alloc(32, byte).toString("base64url")));
  for (const encoded of [Buffer.alloc(31).toString("base64url"), Buffer.alloc(33).toString("base64url"), `${"A".repeat(43)}=`, `${"A".repeat(42)}B`]) assert.ok(!verifier.test(encoded));
});

test("D-136 generated schemas are available through the package's public type exports", async () => {
  const index = await readFile(new URL("index.ts", import.meta.url), "utf8");
  const types = await readFile(new URL("types.ts", import.meta.url), "utf8");
  const registry = types.slice(types.indexOf("export interface components"), types.indexOf("export interface Resource"));
  for (const name of [...Object.keys(teamDefinitions().schemas), "OrganizationPreconditionFailedProblem", "OrganizationPreconditionRequiredProblem", "OrganizationUpdateCommitOutcomeUnknownProblem"]) {
    assert.match(index, new RegExp(`^  ${name},$`, "m"));
    assert.match(registry, new RegExp(`^    ${name}: ${name};$`, "m"));
  }
  assert.doesNotMatch(registry, /^    (Member|Invitation): Resource;$/m);
});

for (const [name, mutate] of [
  ["initial-scope", d => { d.paths["/auth/device"].post["x-scoplen-initial-device-scope"] = "teams:manage"; }],
  ["create-scope", d => { d.paths[invitation].post["x-scoplen-required-device-scope"] = "teams:join"; }],
  ["create-policy", d => { d.paths[invitation].post["x-scoplen-cedar-action"] = "manage_organization"; }],
  ["missing-device-authentication", d => { d.paths[accept].post.security = []; }],
  ["missing-dpop", d => { delete d.paths[dissolve].post.security[0].dpopProof; }],
  ["preview-any-of-scope", d => { d.paths[preview].get["x-scoplen-accepted-device-scopes"] = ["teams:manage"]; }],
  ["preview-single-scope", d => { d.paths[preview].get["x-scoplen-required-device-scope"] = "teams:manage"; }],
  ["self-leave-any-of-scope", d => { d.paths[member].delete["x-scoplen-accepted-device-scopes"] = ["teams:join"]; }],
  ["accept-scope", d => { d.paths[accept].post["x-scoplen-required-device-scope"] = "account:read"; }],
  ["dissolve-policy", d => { d.paths[dissolve].post["x-scoplen-cedar-action"] = "manage_members"; }],
  ["unknown-create-field", d => { d.components.schemas.TeamInvitationCreateRequest.additionalProperties = true; }],
  ["password-length", d => { d.components.schemas.TeamInvitationAcceptRequest.properties.password.maxLength++; }],
  ["verifier-length", d => { d.components.schemas.TeamInvitationCreateRequest.properties.password_verifier.maxLength--; }],
  ["recipient-name", d => { d.components.schemas.TeamInvitationCreateRequest.properties.recipient_username.pattern = ".*"; }],
  ["missing-recipient", d => { d.components.schemas.TeamInvitationResource.properties.data.required.splice(2, 1); }],
  ["missing-team-name", d => { delete d.components.schemas.TeamInvitationResource.properties.data.properties.organization_name; }],
  ["role-limit", d => { d.components.schemas.TeamMemberUpdateRequest.properties.roles.maxItems++; }],
  ["duplicate-roles", d => { d.components.schemas.TeamInvitationCreateRequest.properties.roles.uniqueItems = false; }],
  ["unknown-role", d => { d.components.schemas.TeamRole.enum.push("custom"); }],
  ["member-reactivation", d => { d.components.schemas.TeamMemberUpdateRequest.properties.status.enum.push("removed"); }],
  ["locked-invitation", d => { d.components.schemas.TeamInvitationStatus.enum.pop(); }],
  ["accepted-membership", d => { delete d.components.schemas.TeamInvitationResource.properties.data.allOf; }],
  ["page-bound", d => { d.components.schemas.TeamInvitationPage["x-scoplen-max-bytes"]++; }],
  ["response-extensions", d => { d.components.schemas.TeamAcceptanceReceipt.additionalProperties = false; }],
  ["receipt-account", d => { delete d.components.schemas.TeamAcceptanceReceipt.properties.account_id; }],
  ["request-budget", d => { d.paths[accept].post["x-scoplen-request-max-bytes"]++; }],
  ["response-budget", d => { d.paths[dissolve].post["x-scoplen-response-max-bytes"]++; }],
  ["original-key", d => { d.paths[accept].post.parameters[2].required = false; }],
  ["original-dissolve-tag", d => { d.paths[dissolve].post.parameters[1].required = false; }],
  ["member-tag", d => { d.paths[member].patch.parameters[2].required = false; }],
  ["extra-list-query", d => { d.paths[invitation].get.parameters.push({ name: "recipient" }); }],
  ["cache", d => { delete d.paths[preview].get.responses["200"].headers.Pragma; }],
  ["etag", d => { delete d.paths[member].get.responses["200"].headers.ETag; }],
  ["request-id", d => { delete d.paths[dissolve].post.responses["200"].headers["X-Request-ID"]; }],
  ["retry-header", d => { delete d.components.responses.TeamRateLimited.headers["Retry-After"]; }],
  ["static-denial", d => { d.components.schemas.TeamInvitationDeniedProblem.allOf[1].properties.changed.const = true; }],
  ["oversized-body", d => { delete d.paths[accept].post.responses["413"]; }],
  ["stale-precondition", d => { delete d.paths[member].delete.responses["412"]; }],
  ["required-precondition", d => { delete d.paths[dissolve].post.responses["428"]; }],
  ["accept-unknown-commit", d => { d.paths[accept].post.responses["503"].content["application/problem+json"].schema.oneOf.pop(); }],
  ["delete-unknown-retry", d => { d.paths[member].delete.responses["503"].content["application/problem+json"].schema.oneOf[1].$ref = "#/components/schemas/OrganizationCommitOutcomeUnknownProblem"; }],
  ["generic-member-create", d => { d.paths[members].post = {}; }],
  ["generic-invitation-update", d => { d.paths[preview].patch = {}; }],
  ["retired-invitation-id", d => { d.paths["/orgs/{org}/invitations/{id}"] = {}; }],
  ["retired-member-id", d => { d.paths["/orgs/{org}/members/{id}"] = {}; }],
]) test(`D-136 detects ${name} drift`, () => {
  const changed = structuredClone(document);
  mutate(changed);
  assert.throws(() => generateTeamTypes(changed), /D-136/);
});
