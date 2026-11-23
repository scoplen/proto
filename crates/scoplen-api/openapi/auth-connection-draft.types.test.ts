// SPDX-License-Identifier: Apache-2.0
import type { AuthConnectionDraftCreate, AuthConnectionDraftResource, DraftLoginAttempt, DraftLoginCredentials, DraftLoginStarted, components } from "./index";

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
