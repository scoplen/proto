// SPDX-License-Identifier: Apache-2.0
import type { AuthConnectionDraftCreate, AuthConnectionDraftResource, components } from "./index";

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
