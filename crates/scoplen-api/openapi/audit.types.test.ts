// SPDX-License-Identifier: Apache-2.0
import type { AuditEvent, AuditPage, AuditListQuery, AuditRangeQuery, AuditVerification, components } from "./index";

const event: AuditEvent = {
  organization_id: "0191d3e0-8000-7000-8000-000000000001", sequence: "18446744073709551615",
  occurred_at: "2026-11-17T00:00:00.001Z", category: "unknown", event_class: "future.unclassified",
  outcome: "unknown", actor_account_id: null, actor_device_id: null, actor_browser_family_id: null,
  resource: null, previous_hash: "0".repeat(64), event_hash: "1".repeat(64),
};
const page: AuditPage = { items: [event], next_cursor: null };
const grant: AuditEvent = { ...event, category: "authorization", event_class: "organization.grants_created", resource: { kind: "grant", id: event.organization_id } };
const request: AuditEvent = { ...event, category: "authorization", event_class: "organization.access_request_created", resource: { kind: "access_request", id: event.organization_id } };
const draft: AuditEvent = { ...event, category: "scoplen", outcome: "success", event_class: "organization.auth_draft_created", resource: { kind: "auth_connection_draft", id: "0191d3e0-8000-7000-8000-000000000006" } };
// @ts-expect-error The HTTP path spelling is not an Audit resource kind.
const draftPathAsKind: AuditEvent = { ...draft, resource: { ...draft.resource!, kind: "auth-connection-draft" } };
// @ts-expect-error Audit resource kinds remain a finite, exact registry.
const unknownKind: AuditEvent = { ...event, resource: { kind: "grants", id: event.organization_id } };
const component: components["schemas"]["AuditEvent"] = event;
const query: AuditListQuery = { limit: 50, cursor: "18446744073709551615", sort: "-sequence", filter: 'outcome eq "unknown"' };
const range: AuditRangeQuery = { from_sequence: "1", to_sequence: "4096" };
const result: AuditVerification = { organization_id: event.organization_id, ...range, checked_events: "0", valid: false, failure_sequence: "1", previous_hash: null, head_hash: null, checkpoint: null, uncheckpointed_from_sequence: null };
// @ts-expect-error Exact sequence values never pass through JavaScript numbers.
const rounded: AuditEvent = { ...event, sequence: 9007199254740992 };
// @ts-expect-error Nullable attribution fields are required, even for unknown history.
const missing: AuditEvent = { organization_id: event.organization_id, sequence: "1" };
// @ts-expect-error Verification counts also retain exact decimal strings.
const numericCount: AuditVerification = { ...result, checked_events: 0 };
// @ts-expect-error Descending sequence is the only accepted sort.
const reordered: AuditListQuery = { sort: "occurred_at" };
void [page, grant, request, draft, draftPathAsKind, unknownKind, component, query, range, result, rounded, missing, numericCount, reordered];
