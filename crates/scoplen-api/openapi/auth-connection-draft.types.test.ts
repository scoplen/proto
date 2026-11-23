// SPDX-License-Identifier: Apache-2.0
import type { AuthConnectionDraftCreate, AuthConnectionDraftResource, DraftLoginAttempt, DraftLoginCredentials, DraftLoginStarted, components } from "./index";
import type { AuthConnectionActivation, AuthConnectionActivationStarted, AuthConnectionCandidate, AuthConnectionCondition, AuthConnectionResource } from "./index";

const input: AuthConnectionDraftCreate = { data: { issuer: "https://issuer.example/tenant/" } };
const typedInput: components["schemas"]["AuthConnectionDraftCreate"] = input;
const generation = "0191d3e0-8000-7000-8000-000000000002";
const item: AuthConnectionDraftResource = {
  id: generation, etag: '"' + generation + '"', created_at: "2026-10-26T00:00:00Z", updated_at: "2026-10-26T00:00:00Z",
  data: { organization_id: "0191d3e0-8000-7000-8000-000000000001", issuer: input.data.issuer },
};
const typedResult: components["schemas"]["AuthConnectionDraftResource"] = item;
// @ts-expect-error A draft accepts only the issuer.
const credential: AuthConnectionDraftCreate = { data: { issuer: input.data.issuer, client_secret: "" } };
// @ts-expect-error The server assigns every generation.
const chosen: AuthConnectionDraftCreate = { id: generation, data: input.data };
void [typedInput, typedResult, credential, chosen];

const login: DraftLoginCredentials = { client_id: "fixture", client_secret: "fixture-secret" };
const status: DraftLoginAttempt = { id: generation, draft_generation: generation, organization_id: item.data.organization_id, status: "verified", expires_at: "2026-11-23T00:05:00Z" };
const started: DraftLoginStarted = { ...status, status: "pending", authorization_url: "https://issuer.example/authorize?state=fixture" };
const typedLogin: components["schemas"]["DraftLoginCredentials"] = login;
const typedStatus: components["schemas"]["DraftLoginAttempt"] = status;
const typedStarted: components["schemas"]["DraftLoginStarted"] = started;
// @ts-expect-error Callers cannot provide an OAuth redirect or tenant override.
const modifiedLogin: DraftLoginCredentials = { ...login, redirect_uri: "https://example.test" };
// @ts-expect-error Status reads cannot return the start-only authorization URL.
const unsafeStatus: DraftLoginAttempt = started;
// @ts-expect-error Start always returns a pending attempt.
const alreadyVerified: DraftLoginStarted = { ...started, status: "verified" };
void [typedLogin, typedStatus, typedStarted, modifiedLogin, unsafeStatus, alreadyVerified];

const candidate: AuthConnectionCandidate = { ...login, draft_generation: generation, space_id: "spc_team" };
const typedCandidate: components["schemas"]["AuthConnectionCandidate"] = candidate;
const connection: AuthConnectionResource = {
  id: generation, etag: item.etag, created_at: item.created_at, updated_at: item.created_at,
  data: { organization_id: item.data.organization_id, status: "active", issuer: item.data.issuer, client_id: login.client_id, space_id: candidate.space_id },
};
const typedConnection: components["schemas"]["AuthConnectionResource"] = connection;
const attempt: AuthConnectionActivation = { ...status, status: "verified", expected_revision: null, issuer: connection.data.issuer, client_id: login.client_id, space_id: candidate.space_id };
const typedAttempt: components["schemas"]["AuthConnectionActivation"] = attempt;
const navigating: AuthConnectionActivationStarted = { ...attempt, status: "pending", authorization_url: started.authorization_url };
const typedNavigation: components["schemas"]["AuthConnectionActivationStarted"] = navigating;
const expectedEmpty: AuthConnectionCondition = { "If-None-Match": "*" };
const expectedRevision: AuthConnectionCondition = { "If-Match": item.etag };
const installed: components["schemas"]["AuthConnectionActiveResource"] = { ...connection, data: { ...connection.data, status: "active" } };
const suspended: components["schemas"]["AuthConnectionSuspendedResource"] = { ...connection, data: { ...connection.data, status: "suspended" } };
// @ts-expect-error Only confirmation of a suspension can return this receipt.
const wrongTransition: typeof installed = suspended;
// @ts-expect-error A family may supply exactly one expected connection head.
const conflictingHeads: AuthConnectionCondition = { "If-Match": item.etag, "If-None-Match": "*" };
// @ts-expect-error A GET representation cannot carry the one-time navigation.
const unsafeAttempt: AuthConnectionActivation = navigating;
// @ts-expect-error Access tokens cannot appear as resource extensions.
const disclosed: AuthConnectionResource = { ...connection, access_token: "disallowed" };
// @ts-expect-error A provider secret cannot appear in connection metadata.
const nestedDisclosure: AuthConnectionResource = { ...connection, data: { ...connection.data, client_secret: "disallowed" } };
// @ts-expect-error A caller may not override the draft's issuer on activation.
const modifiedCandidate: AuthConnectionCandidate = { ...candidate, issuer: item.data.issuer };
void [typedCandidate, typedConnection, typedAttempt, typedNavigation, expectedEmpty, expectedRevision, installed, suspended, wrongTransition, conflictingHeads, unsafeAttempt, disclosed, nestedDisclosure, modifiedCandidate];
