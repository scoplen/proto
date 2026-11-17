// SPDX-License-Identifier: Apache-2.0
import type { AccessRequestFields, AccessRequestCheckRequest, AccessRequestCheckResponse, AccessRequestCreateRequest, AccessRequestDecisionRequest, AccessRequestStatus, AccessRequestView, AccessRequestDecision, AccessRequestGrant, AccessRequestResource, AccessRequestPage, AccessRequestListQuery, SimpleRuleInput, components } from "./index";

const id = "0191d3e0-8000-7000-8000-000000000001";
const fields: AccessRequestFields = { host: id, remote_user: "deploy", duration_seconds: 300, reason: "Scheduled maintenance" };
const check: AccessRequestCheckRequest = { data: fields };
const checked: AccessRequestCheckResponse = { allowed: true, future_extension: true };
const create: AccessRequestCreateRequest = { id, data: fields };
const decide: AccessRequestDecisionRequest = { decision: "approve" };
const status: AccessRequestStatus = "future_status";
const view: AccessRequestView = "approvals";
const decision: AccessRequestDecision = { outcome: "approve", actor_account_id: id, decided_at: "2026-11-17T00:00:00.5Z", extension: true };
const grant: AccessRequestGrant = { id, valid_from: "2026-11-17T00:00:00Z", valid_until: "2026-11-17T00:05:00Z" };
const resource: AccessRequestResource = { id, etag: '"request"', created_at: "2026-11-17T00:00:00Z", updated_at: "2026-11-17T00:00:00Z", data: { ...fields, requester_account_id: id, requester_membership_id: id, expires_at: "2026-11-18T00:00:00Z", status: "approved", decision, grant, extension: {} }, extension: true };
const component: components["schemas"]["AccessRequestResource"] = resource;
const page: AccessRequestPage = { items: [resource], next_cursor: null, extension: [] };
const query: AccessRequestListQuery = { view, limit: 50, cursor: id };
const rule: SimpleRuleInput = { organization: id, membership: id, request_access: [id] };
const groupRule: SimpleRuleInput = { organization: id, group: id, request_access: [id] };
// @ts-expect-error Request creation requires its caller-selected immutable id.
const missingId: AccessRequestCreateRequest = { data: fields };
// @ts-expect-error The server chooses requester and Membership identities.
const requester: AccessRequestFields = { ...fields, requester_account_id: id };
// @ts-expect-error The initial profile accepts one exact Host, never HostGroups.
const hostGroups: AccessRequestFields = { ...fields, host_groups: [id] };
// @ts-expect-error Request fields are complete, including the reason.
const missingReason: AccessRequestFields = { host: id, remote_user: "deploy", duration_seconds: 300 };
// @ts-expect-error Duration is a JSON integer represented by a number.
const textualDuration: AccessRequestFields = { ...fields, duration_seconds: "300" };
// @ts-expect-error Decisions cannot replace or redact the original reason.
const changedReason: AccessRequestDecisionRequest = { decision: "deny", reason: "other" };
// @ts-expect-error No request revocation operation exists in this profile.
const revoke: AccessRequestDecisionRequest = { decision: "revoke" };
// @ts-expect-error Check responses require the actual eligibility result.
const missingAllowed: AccessRequestCheckResponse = {};
// @ts-expect-error Approval Grant history is always finite.
const endless: AccessRequestGrant = { ...grant, valid_until: null };
// @ts-expect-error A listing requires an explicit mine or approvals view.
const missingView: AccessRequestListQuery = { limit: 50 };
// @ts-expect-error Request listing has no generic filter/sort query.
const filter: AccessRequestListQuery = { view: "mine", sort: "-updated_at" };
// @ts-expect-error Future status strings do not create future list views.
const futureView: AccessRequestView = "all";
// @ts-expect-error Simple rules contain exactly one independent rule.
const combined: SimpleRuleInput = { organization: id, membership: id, request_access: [id], view: [{ type: 1, id }] };
// @ts-expect-error Request rules cannot select both Membership and Group.
const twoSubjects: SimpleRuleInput = { organization: id, membership: id, group: id, request_access: [id] };
// @ts-expect-error Request rules contain direct Host ids, not connect selectors.
const hostGroupRule: SimpleRuleInput = { organization: id, membership: id, request_access: { hosts: [id], host_groups: [] } };
// @ts-expect-error The provisional generic decision schema has been removed.
type OldDecision = components["schemas"]["DecisionRequest"];
// @ts-expect-error The provisional generic request schema has been removed.
type OldRequest = components["schemas"]["AccessRequest"];
void [check, checked, create, decide, status, component, page, query, rule, groupRule, missingId, requester, hostGroups, missingReason, textualDuration, changedReason, revoke, missingAllowed, endless, missingView, filter, futureView, combined, twoSubjects, hostGroupRule];
