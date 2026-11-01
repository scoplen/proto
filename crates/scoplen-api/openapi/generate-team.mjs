// SPDX-License-Identifier: Apache-2.0
// D-136 exact named-Account invitation and membership lifecycle contract.
import { isDeepStrictEqual } from "node:util";

export const initialTeamDeviceScope = "account:read keys:read keys:write orgs:create orgs:read orgs:write sync:read sync:write teams:join teams:manage";
const uuid = { type: "string", format: "uuid", pattern: "^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$" };
const ref = name => ({ $ref: `#/components/schemas/${name}` });
const object = (properties, request = false) => ({ type: "object", additionalProperties: !request, required: Object.keys(properties), properties });
const username = { type: "string", minLength: 3, maxLength: 64, pattern: "^[a-z0-9][a-z0-9._-]*$" };
const name = { type: "string", minLength: 1, maxLength: 128, "x-scoplen-max-utf8-bytes": 128, description: "1..128 UTF-8 bytes, no Unicode control or leading/trailing Unicode whitespace; preserve without normalization." };
const timestamp = { type: "string", format: "date-time", pattern: "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-5][0-9](\\.[0-9]+)?Z$", description: "A valid UTC calendar timestamp." };
const etag = { type: "string", pattern: '^"[!#-~]*"$', minLength: 2, maxLength: 256 };
const roles = { type: "array", minItems: 1, maxItems: 5, uniqueItems: true, items: ref("TeamRole"), description: "Distinct built-in roles; encoders sort bytewise, readers accept distinct order. No role value grants authority without current server checks." };
const headers = {
  "Cache-Control": { required: true, schema: { type: "string", const: "no-store" } },
  Pragma: { required: true, schema: { type: "string", const: "no-cache" } },
  "X-Request-ID": { required: true, schema: { type: "string", minLength: 1 } },
};
const orgParameter = { name: "org", in: "path", required: true, schema: uuid };
const pathParameter = name => ({ name, in: "path", required: true, schema: uuid });
const idempotency = { name: "Idempotency-Key", in: "header", required: true, schema: uuid };
const ifMatch = { name: "If-Match", in: "header", required: true, description: "Exactly one original strong ETag; no weak tag, wildcard, multiple values or silent refresh/replay.", schema: etag };
const pagination = [
  { name: "limit", in: "query", required: false, schema: { type: "integer", minimum: 1, maximum: 500, default: 50 } },
  { name: "cursor", in: "query", required: false, schema: uuid },
];
const baseDescription = "Require current Account/Device authentication, actual-method/trusted-URL DPoP and durable replay protection. JWT org snapshots and submitted roles are not current authority. No refresh cookie is read or changed. ";
const mutationDescription = "Independent durable team admission charges 30 source and 10 authenticated-Account attempts per mutation operation per 60 seconds, sharing the bounded existing admission storage. A required audit failure rolls back business mutation. ";
const receiptDescription = "One original UUIDv7 key and canonical payload bind the authenticated Account and actual method/path for 24 hours. Changed payload under the same key conflicts. Unconfirmed COMMIT preserves the exact original operation; explicit confirmation uses fresh DPoP only within that original window. Never automatically replace an expired key. ";
const resource = data => ({ ...object({ id: uuid, etag, created_at: timestamp, updated_at: timestamp, data }), "x-scoplen-max-bytes": 4096 });
const page = schema => ({ ...object({ items: { type: "array", maxItems: 500, items: ref(schema), description: "Distinct ascending ids beyond the requested cursor; each original item including extensions/whitespace is at most 4096 bytes." }, next_cursor: { anyOf: [uuid, { type: "null" }], description: "Non-null only when more eligible items exist; equals the nonempty Page's final id." } }), "x-scoplen-max-bytes": 2097152 });
const success = (schema, bound, individual = false) => ({
  description: `Complete JSON body <=${bound} bytes; response extensions are ignored within this bound.${individual ? " HTTP ETag exactly equals body etag." : ""}`,
  headers: { ...headers, ...(individual ? { ETag: { required: true, description: "Strong validator exactly equal to body etag.", schema: etag } } : {}) },
  content: { "application/json": { schema: ref(schema) } },
});
const request = (schema, bound) => ({ required: true, description: `Complete UTF-8 JSON <=${bound} bytes; reject unknown fields and recursive duplicate names before mutation.`, content: { "application/json": { schema: ref(schema) } } });
const problem = suffix => ({ $ref: `#/components/responses/Organization${suffix}` });
const teamProblem = suffix => ({ $ref: `#/components/responses/Team${suffix}` });
const storage = (mutation, receipt) => ({
  description: mutation ? (receipt ? "Confirmed rollback is changed=false/retryable=true. Unconfirmed COMMIT is changed=true/retryable=true and permits only explicit original-operation confirmation within 24 hours." : "Confirmed rollback is changed=false/retryable=true. Unconfirmed COMMIT is changed=true/retryable=false; refresh and review, never automatically resubmit.") : "Storage failure is changed=false/retryable=true; no partial success body.",
  headers,
  content: { "application/problem+json": { schema: mutation ? { oneOf: [ref("OrganizationStorageUnavailableProblem"), ref(receipt ? "OrganizationCommitOutcomeUnknownProblem" : "OrganizationUpdateCommitOutcomeUnknownProblem")] } : ref("OrganizationStorageUnavailableProblem") } },
});
const failures = (mutation = false, receipt = false) => ({
  "400": problem("InvalidRequest"), "401": problem("AuthenticationRequired"), "403": problem("Denied"), "404": problem("NotFound"),
  ...(mutation ? { "409": problem("Conflict"), "429": teamProblem("RateLimited") } : {}),
  "503": storage(mutation, receipt),
  default: { description: "Bounded shared problem <=4096 bytes; no partial success or sensitive payload.", headers, content: { "application/problem+json": { schema: ref("ProblemDetails") } } },
});
const conditionalFailures = { "412": problem("PreconditionFailed"), "428": problem("PreconditionRequired") };
const bodyFailures = { "413": teamProblem("BodyTooLarge"), "415": problem("ContentType") };

export function teamDefinitions() {
  const invitationData = object({ organization_id: uuid, organization_name: name, recipient_account_id: uuid, recipient_username: username, roles, issuer_account_id: uuid, expires_at: timestamp, status: ref("TeamInvitationStatus"), membership_id: { anyOf: [uuid, { type: "null" }] } });
  invitationData.allOf = [{ if: { properties: { status: { const: "accepted" } } }, then: { properties: { membership_id: uuid } }, else: { properties: { membership_id: { type: "null" } } } }];
  const schemas = {
    TeamRole: { type: "string", enum: ["administrator", "approver", "member", "owner", "security_auditor"] },
    TeamInvitationStatus: { type: "string", enum: ["pending", "accepted", "revoked", "expired", "locked"] },
    TeamMemberStatus: { type: "string", enum: ["active", "suspended", "removed"] },
    TeamInvitationCreateRequest: { ...object({ invitation_id: uuid, recipient_username: username, roles, password_verifier: { type: "string", minLength: 43, maxLength: 43, pattern: "^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$", writeOnly: true, description: "Canonical unpadded base64url of the exact 32-byte shared K-2 context-bound verifier; never the password. Server storage retains only this verifier." } }, true), "x-scoplen-max-bytes": 4096 },
    TeamInvitationAcceptRequest: { ...object({ password: { type: "string", minLength: 8, maxLength: 8, pattern: "^[0123456789ABCDEFGHJKMNPQRSTVWXYZ]{8}$", writeOnly: true, description: "Separate transient invitation password, exactly eight uppercase ASCII symbols with no aliases, case folding, spaces or separators. Never an Account password or key." } }, true), "x-scoplen-max-bytes": 256 },
    TeamInvitationResource: resource(invitationData),
    TeamInvitationPage: page("TeamInvitationResource"),
    TeamMemberUpdateRequest: { ...object({ roles, status: { type: "string", enum: ["active", "suspended"] } }, true), "x-scoplen-max-bytes": 1024 },
    TeamMemberResource: resource(object({ organization_id: uuid, account_id: uuid, username, roles, status: ref("TeamMemberStatus") })),
    TeamMemberPage: page("TeamMemberResource"),
    TeamAcceptanceReceipt: { ...object({ invitation_id: uuid, organization_id: uuid, account_id: uuid, membership_id: uuid, accepted_at: timestamp }), "x-scoplen-max-bytes": 1024, description: "Immutable historical acceptance confirmation; bind every echoed id to the captured request. It never proves current membership or recreates removed authority." },
    TeamDissolveRequest: { ...object({ organization_id: uuid }, true), "x-scoplen-max-bytes": 256 },
    TeamDissolutionReceipt: { ...object({ organization_id: uuid, dissolved_at: timestamp }), "x-scoplen-max-bytes": 512, description: "Historical dissolution confirmation only; bind the Organization to the original request. It grants no retained team-data access." },
  };
  const responses = {};
  for (const [suffix, status, code, retryable] of [
    ["InvitationDenied", 409, "organization.invitation_denied", false],
    ["BodyTooLarge", 413, "organization.invalid_request", false],
  ]) {
    const schema = `Team${suffix}Problem`;
    schemas[schema] = { allOf: [ref("ProblemDetails"), { type: "object", properties: { status: { const: status }, code: { const: code }, changed: { const: false }, retryable: { const: retryable } } }] };
    responses[`Team${suffix}`] = { description: `${status} ${code}; changed=false; retryable=${retryable}. Complete problem <=4096 bytes.${suffix === "InvitationDenied" ? " Static detail does not distinguish recipient eligibility, password, expiry, lock or current issuer failure." : ""}`, headers, content: { "application/problem+json": { schema: ref(schema) } } };
  }
  const delay = "(?:[1-9]|[1-9][0-9]|[12][0-9]{2}|300)";
  responses.TeamRateLimited = { description: "Durable team-operation admission denied; changed=false/retryable=true. Retry-After is the greatest applicable wait rounded to 1..300 seconds, not an admission guarantee. Existing bounded authentication rate headers expose no private bucket or invitation counter.", headers: { "Retry-After": { required: true, schema: { type: "string", pattern: `^${delay}$` } }, "RateLimit-Policy": { required: true, schema: { const: '"authentication";q=30;w=60' } }, RateLimit: { required: true, schema: { type: "string", pattern: `^"authentication";r=0;t=${delay}$` }, description: "The t delay equals Retry-After." }, ...headers }, content: { "application/problem+json": { schema: ref("AuthRateLimitedProblem") } } };
  const paths = {
    "/orgs/{org}/invitations": {
      get: {
        operationId: "listTeamInvitations", "x-scoplen-required-device-scope": "teams:manage", "x-scoplen-cedar-action": "manage_members", "x-scoplen-response-max-bytes": 2097152,
        description: `${baseDescription}Require current active membership and manage_members. Return ascending Invitation Resources without password, verifier or failure count. Reject body, unknown/duplicate query names, If-Match and Idempotency-Key.`,
        parameters: [orgParameter, ...pagination], responses: { "200": success("TeamInvitationPage", 2097152), ...failures() },
      },
      post: {
        operationId: "createTeamInvitation", "x-scoplen-required-device-scope": "teams:manage", "x-scoplen-cedar-action": "manage_members", "x-scoplen-request-max-bytes": 4096, "x-scoplen-response-max-bytes": 4096,
        description: `${baseDescription}${mutationDescription}${receiptDescription}Resolve recipient_username to one existing eligible Account and bind its id permanently. Active members are ineligible; suspended membership is restored only by authorized member update. Owner grants require current Owner; other built-in roles require manage_members. Persist issuer, roles, verifier, 24-hour expiry, invitation and audit atomically. Exact replay still requires current administrative authority and returns the current Resource without renewing expiry. Reject query and If-Match; ids cannot be reused.`,
        parameters: [orgParameter, idempotency], requestBody: request("TeamInvitationCreateRequest", 4096),
        responses: { "201": success("TeamInvitationResource", 4096, true), ...failures(true, true), ...bodyFailures, "409": { description: "Changed payload/id conflict or static invitation denial for unknown/ineligible recipient.", headers, content: { "application/problem+json": { schema: { oneOf: [ref("OrganizationConflictProblem"), ref("TeamInvitationDeniedProblem")] } } } } },
      },
    },
    "/orgs/{org}/invitations/{invitation}": {
      get: {
        operationId: "getTeamInvitation", "x-scoplen-accepted-device-scopes": ["teams:join", "teams:manage"], "x-scoplen-response-max-bytes": 4096,
        description: `${baseDescription}Either teams:manage plus current manage_members, or teams:join plus the fixed recipient Account. Recipient preview includes the team name but no password/verifier/counter. A different Account receives the same static 404 as absence and consumes no attempt. Reject body, every query, If-Match and Idempotency-Key.`,
        parameters: [orgParameter, pathParameter("invitation")], responses: { "200": success("TeamInvitationResource", 4096, true), ...failures() },
      },
      delete: {
        operationId: "revokeTeamInvitation", "x-scoplen-required-device-scope": "teams:manage", "x-scoplen-cedar-action": "manage_members",
        description: `${baseDescription}${mutationDescription}Authorize before comparing the original Invitation ETag. Pending or locked becomes revoked with one audit; already revoked with matching current ETag is a no-op. Accepted/expired conflicts. This never removes membership. Reject body, every query and Idempotency-Key.`,
        parameters: [orgParameter, pathParameter("invitation"), ifMatch], responses: { "204": { description: "Revoked or matching already-revoked no-op; no body.", headers }, ...failures(true), ...conditionalFailures },
      },
    },
    "/orgs/{org}/invitations/{invitation}/accept": { post: {
      operationId: "acceptTeamInvitation", "x-scoplen-required-device-scope": "teams:join", "x-scoplen-request-max-bytes": 256, "x-scoplen-response-max-bytes": 1024,
      description: `${baseDescription}${mutationDescription}${receiptDescription}Only the fixed recipient Account may submit the separate password. After transaction locks require pending/unexpired invitation, no active recipient membership and current issuer/role-grant authority; compare the shared context-bound verifier in constant time. Five incorrect recipient submissions lock it; foreign Accounts return static 404 and never charge that counter. Atomically create one membership, consume invitation, revoke derived access as required and audit. Exact accepted-receipt replay follows current Account/Device plus key/payload binding before team/pending/password/issuer checks; it confirms history only and cannot reactivate removed membership. Reject query and If-Match. No Account/Device enrollment, Personal key delivery or Shared vault.`,
      parameters: [orgParameter, pathParameter("invitation"), idempotency], requestBody: request("TeamInvitationAcceptRequest", 256),
      responses: { "200": success("TeamAcceptanceReceipt", 1024), ...failures(true, true), ...bodyFailures, "409": { description: "Changed receipt binding conflicts; static invitation denial covers invalid password, unavailable/expired/locked invitation or lost issuer authority.", headers, content: { "application/problem+json": { schema: { oneOf: [ref("OrganizationConflictProblem"), ref("TeamInvitationDeniedProblem")] } } } } },
    } },
    "/orgs/{org}/members": { get: {
      operationId: "listTeamMembers", "x-scoplen-required-device-scope": "teams:manage", "x-scoplen-cedar-action": "manage_members", "x-scoplen-response-max-bytes": 2097152,
      description: `${baseDescription}Require current active membership and manage_members. Return only this team's ascending Member Resources, never email, Devices, Personal data or keys. Reject body, unknown/duplicate query names, If-Match and Idempotency-Key. There is no direct member-create operation; named invitation acceptance is required.`,
      parameters: [orgParameter, ...pagination], responses: { "200": success("TeamMemberPage", 2097152), ...failures() },
    } },
    "/orgs/{org}/members/{membership}": {
      get: {
        operationId: "getTeamMember", "x-scoplen-required-device-scope": "teams:manage", "x-scoplen-cedar-action": "manage_members", "x-scoplen-response-max-bytes": 4096,
        description: `${baseDescription}Require current active membership and manage_members; target belongs to path Organization. Reject body, every query, If-Match and Idempotency-Key.`,
        parameters: [orgParameter, pathParameter("membership")], responses: { "200": success("TeamMemberResource", 4096, true), ...failures() },
      },
      patch: {
        operationId: "updateTeamMember", "x-scoplen-required-device-scope": "teams:manage", "x-scoplen-cedar-action": "manage_members", "x-scoplen-request-max-bytes": 1024, "x-scoplen-response-max-bytes": 4096,
        description: `${baseDescription}${mutationDescription}Require current manage_members before comparing the original Member ETag. Only a current Owner may grant owner or edit/suspend a current Owner. Preserve at least one active Owner, even under custom permit-all policy. Removed members cannot reactivate by PATCH; suspended members can. Equal matching update is a no-op. Atomic mutation updates authority/view revision, revokes required derived access and audits. Reject every query and Idempotency-Key. Unknown COMMIT requires refresh/review with no automatic replay.`,
        parameters: [orgParameter, pathParameter("membership"), ifMatch], requestBody: request("TeamMemberUpdateRequest", 1024), responses: { "200": success("TeamMemberResource", 4096, true), ...failures(true), ...bodyFailures, ...conditionalFailures },
      },
      delete: {
        operationId: "removeTeamMember", "x-scoplen-accepted-device-scopes": ["teams:join", "teams:manage"],
        description: `${baseDescription}${mutationDescription}Either teams:manage plus current manage_members, or teams:join for exactly the caller's membership (self-leave). Only a current Owner may remove a current Owner; always preserve an active Owner. Self-leave may use the original current caller-membership projection ETag from section 2.9 instead of the administrator-only Member ETag; compare that same projection. A matching already-removed state is a no-op only with current caller authority. Revoke team-derived access and invalidate only this team's work; retain Personal and other teams. Reject body, every query and Idempotency-Key. Direct certificates retain their actual expiry/KRL limits; no unmanaged SSH termination claim.`,
        parameters: [orgParameter, pathParameter("membership"), ifMatch], responses: { "204": { description: "Removed or authorized matching already-removed no-op; no body.", headers }, ...failures(true), ...conditionalFailures },
      },
    },
    "/orgs/{org}/dissolve": { post: {
      operationId: "dissolveTeam", "x-scoplen-required-device-scope": "teams:manage", "x-scoplen-cedar-action": "manage_organization", "x-scoplen-request-max-bytes": 256, "x-scoplen-response-max-bytes": 512,
      description: `${baseDescription}${mutationDescription}${receiptDescription}Require current active Owner and manage_organization, exact current Organization ETag and echoed Organization id. Atomically disable this team, revoke memberships/invitations/grants/derived access, withdraw inventory from serving and commit final team audit plus receipt; keep Accounts, Personal data and other teams. Installed host trust is removed separately. Bind the receipt to the original strong If-Match as well as body; explicit retry preserves it. Exact receipt confirmation occurs before active-team/Owner/current-ETag lookup, never grants retained-data access or proves current authority. Without an exact receipt all normal checks apply. Reject every query.`,
      parameters: [orgParameter, ifMatch, idempotency], requestBody: request("TeamDissolveRequest", 256), responses: { "200": success("TeamDissolutionReceipt", 512), ...failures(true, true), ...bodyFailures, ...conditionalFailures },
    } },
  };
  for (const path of Object.values(paths)) {
    for (const operation of Object.values(path)) operation.security = [{ accessToken: [], dpopProof: [] }];
  }
  return { schemas, responses, paths };
}

export function generateTeamTypes(document) {
  const expected = teamDefinitions();
  for (const [section, values] of Object.entries(expected)) {
    const actual = section === "paths" ? document.paths : document.components?.[section];
    for (const [name, value] of Object.entries(values)) {
      if (!isDeepStrictEqual(actual?.[name], value)) throw new Error(`D-136 ${section}.${name} differs from its exact contract`);
    }
  }
  for (const retired of ["/orgs/{org}/invitations/{id}", "/orgs/{org}/members/{id}"]) {
    if (Object.hasOwn(document.paths, retired)) throw new Error(`D-136 retired generic path remains: ${retired}`);
  }
  if (document.paths?.["/auth/device"]?.post?.["x-scoplen-initial-device-scope"] !== initialTeamDeviceScope) throw new Error("D-136 initial Device scope differs from its exact contract");
  const lines = [
    'export type TeamRole = "administrator" | "approver" | "member" | "owner" | "security_auditor";',
    'export type TeamInvitationStatus = "pending" | "accepted" | "revoked" | "expired" | "locked";',
    'export type TeamMemberStatus = "active" | "suspended" | "removed";',
    "export interface TeamInvitationCreateRequest { invitation_id: string; recipient_username: string; roles: TeamRole[]; password_verifier: string; }",
    "export interface TeamInvitationAcceptRequest { password: string; }",
    "export interface TeamInvitationResource {",
    "  id: string; etag: string; created_at: string; updated_at: string;",
    "  data: { organization_id: string; organization_name: string; recipient_account_id: string; recipient_username: string; roles: TeamRole[]; issuer_account_id: string; expires_at: string; [extension: string]: unknown; } &",
    '    ({ status: "accepted"; membership_id: string } | { status: Exclude<TeamInvitationStatus, "accepted">; membership_id: null });',
    "  [extension: string]: unknown;", "}",
    "export interface TeamInvitationPage { items: TeamInvitationResource[]; next_cursor: string | null; [extension: string]: unknown; }",
    'export interface TeamMemberUpdateRequest { roles: TeamRole[]; status: "active" | "suspended"; }',
    "export interface TeamMemberResource {",
    "  id: string; etag: string; created_at: string; updated_at: string;",
    "  data: { organization_id: string; account_id: string; username: string; roles: TeamRole[]; status: TeamMemberStatus; [extension: string]: unknown };",
    "  [extension: string]: unknown;", "}",
    "export interface TeamMemberPage { items: TeamMemberResource[]; next_cursor: string | null; [extension: string]: unknown; }",
    "/** Historical confirmation only; every echoed id must bind the captured original operation. */",
    "export interface TeamAcceptanceReceipt { invitation_id: string; organization_id: string; account_id: string; membership_id: string; accepted_at: string; [extension: string]: unknown; }",
    "export interface TeamDissolveRequest { organization_id: string; }",
    "/** Historical confirmation only; conveys no current team-data access. */",
    "export interface TeamDissolutionReceipt { organization_id: string; dissolved_at: string; [extension: string]: unknown; }", "",
  ];
  for (const [name, schema] of Object.entries(expected.schemas).filter(([, value]) => value.allOf)) {
    const fields = Object.entries(schema.allOf[1].properties).map(([key, value]) => `${key}: ${JSON.stringify(value.const)}`).join("; ");
    lines.push(`export type ${name} = ProblemDetails & { ${fields}; };`, "");
  }
  return lines.join("\n");
}
