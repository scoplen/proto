// SPDX-License-Identifier: Apache-2.0
import type { GrantFields, GrantCreateRequest, GrantReplaceRequest, GrantResource, GrantPage, GrantListQuery, components } from "./index";

const fields: GrantFields = { membership: "0191d3e0-8000-7000-8000-000000000001", host: "0191d3e0-8000-7000-8000-000000000002", remote_user: "deploy", valid_from: "2026-11-17T00:00:00Z", valid_until: null };
const create: GrantCreateRequest = { id: "0191d3e0-8000-7000-8000-000000000003", data: fields };
const replace: GrantReplaceRequest = { data: { ...fields, valid_until: "2026-11-17T00:05:00Z" } };
const resource: GrantResource = { id: create.id, etag: '"grant"', created_at: fields.valid_from, updated_at: fields.valid_from, data: { ...fields, future: true }, extension: {} };
const component: components["schemas"]["GrantResource"] = resource;
const page: GrantPage = { items: [resource], next_cursor: null, extension: true };
const query: GrantListQuery = { limit: 50, cursor: resource.id };
// @ts-expect-error An explicit valid_until is mandatory even without an expiry.
const missingExpiry: GrantFields = { membership: fields.membership, host: fields.host, remote_user: fields.remote_user, valid_from: fields.valid_from };
// @ts-expect-error Wire validity times are whole-second UTC strings, never JSON numbers.
const numericTime: GrantFields = { ...fields, valid_from: 1794873600 };
// @ts-expect-error Membership cannot be replaced by an Account or username selector.
const accountSelector: GrantFields = { ...fields, account: "operator" };
// @ts-expect-error Complete replacement cannot change the immutable id.
const replaceId: GrantReplaceRequest = { id: create.id, data: fields };
// @ts-expect-error Request data accepts exactly the five writable fields.
const hiddenState: GrantCreateRequest = { id: create.id, data: { ...fields, state: "active" } };
// @ts-expect-error Grant listing has no filter or sort profile.
const filter: GrantListQuery = { filter: "active" };
void [create, replace, component, page, query, missingExpiry, numericTime, accountSelector, replaceId, hiddenState, filter];
