// SPDX-License-Identifier: Apache-2.0
// D-137 exact local-group, persisted-policy and pure simple-rule contracts.
import { isDeepStrictEqual } from "node:util";

const uuid = { type: "string", format: "uuid", pattern: "^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$" };
const ref = name => ({ $ref: `#/components/schemas/${name}` });
const responseRef = name => ({ $ref: `#/components/responses/${name}` });
const object = (properties, request = false) => ({ type: "object", additionalProperties: !request, required: Object.keys(properties), properties });
const name = { type: "string", minLength: 1, maxLength: 128, "x-scoplen-max-utf8-bytes": 128, description: "1..128 UTF-8 bytes, no Unicode control or leading/trailing Unicode whitespace; preserve without normalization." };
const etag = { type: "string", pattern: '^"[!#-~]*"$', minLength: 2, maxLength: 256 };
const timestamp = { type: "string", format: "date-time", pattern: "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-5][0-9](\\.[0-9]+)?Z$", description: "A valid UTC calendar timestamp." };
const ids = (maximum, description) => ({ type: "array", maxItems: maximum, uniqueItems: true, items: uuid, description });
const members = ids(4096, "Distinct canonical UUIDv7 Membership ids, never Account ids; encoders sort by UUID bytes. Every member must be currently active in this Organization.");
const policySource = { type: "string", minLength: 1, maxLength: 65536, "x-scoplen-max-utf8-bytes": 65536, description: "Exactly one non-template strict-schema Cedar policy. Validate known actions and all explicit references against the current Organization. Reject any permit or forbid potentially matching view_inventory that observes context.now, including action sets or unconstrained actions; connect-only time conditions remain supported. Parse the Cedar expression representation rather than matching source substrings. Preserve the authored source." };
const headers = {
  "Cache-Control": { required: true, schema: { type: "string", const: "no-store" } },
  Pragma: { required: true, schema: { type: "string", const: "no-cache" } },
  "X-Request-ID": { required: true, schema: { type: "string", minLength: 1 } },
};
const orgParameter = { name: "org", in: "path", required: true, schema: uuid };
const idParameter = { name: "id", in: "path", required: true, schema: uuid };
const idempotency = { name: "Idempotency-Key", in: "header", required: true, schema: uuid };
const ifMatch = { name: "If-Match", in: "header", required: true, description: "Exactly one original strong ETag; no weak tag, wildcard, multiple values or silent refresh/replay.", schema: etag };
const pagination = [
  { name: "limit", in: "query", required: false, schema: { type: "integer", minimum: 1, maximum: 500, default: 50 } },
  { name: "cursor", in: "query", required: false, schema: uuid },
];
const resource = data => ({ ...object({ id: uuid, etag, created_at: timestamp, updated_at: timestamp, data }), "x-scoplen-max-bytes": 262144 });
const page = schema => ({ ...object({ items: { type: "array", maxItems: 500, items: ref(schema), description: "Distinct ascending ids beyond the requested cursor; each original item including extensions and whitespace is at most 262144 bytes. A shorter nonempty prefix may satisfy the Page byte budget." }, next_cursor: { anyOf: [uuid, { type: "null" }], description: "Non-null only when more eligible items exist; equals the nonempty Page's final id." } }), "x-scoplen-max-bytes": 8388608 });
const request = schema => ({ required: true, description: "Complete UTF-8 JSON <=262144 bytes; reject unknown fields and recursive duplicate names before mutation.", content: { "application/json": { schema: ref(schema) } } });
const success = (schema, individual) => ({
  description: `Complete JSON body <=${individual ? 262144 : 8388608} bytes, including extensions and whitespace; ignore response extensions within that bound.${individual ? " HTTP ETag exactly equals body etag." : " Each original embedded Resource retains its own complete-body bound."}`,
  headers: { ...headers, ...(individual ? { ETag: { required: true, description: "Strong validator exactly equal to body etag.", schema: etag } } : {}) },
  content: { "application/json": { schema: ref(schema) } },
});
const problem = suffix => responseRef(`Organization${suffix}`);
const storage = (mutation, receipt) => ({
  description: mutation ? (receipt ? "Confirmed rollback is changed=false/retryable=true. Unconfirmed COMMIT is changed=true/retryable=true and permits only explicit original-key/payload confirmation within the original 24 hours with fresh DPoP." : "Confirmed rollback is changed=false/retryable=true. Unconfirmed COMMIT is changed=true/retryable=false; refresh and review, never automatically resubmit or substitute an ETag.") : "Storage failure is changed=false/retryable=true; no partial success body.",
  headers,
  content: { "application/problem+json": { schema: mutation ? { oneOf: [ref("OrganizationStorageUnavailableProblem"), ref(receipt ? "OrganizationCommitOutcomeUnknownProblem" : "OrganizationUpdateCommitOutcomeUnknownProblem")] } : ref("OrganizationStorageUnavailableProblem") } },
});
const failures = (mutation = false, receipt = false) => ({
  "400": problem("InvalidRequest"), "401": problem("AuthenticationRequired"), "403": problem("Denied"), "404": problem("NotFound"),
  ...(mutation ? { "409": problem("Conflict"), "429": responseRef("GroupPolicyRateLimited") } : {}),
  "503": storage(mutation, receipt),
  default: { description: "Bounded shared problem <=4096 bytes; no partial success or sensitive payload.", headers, content: { "application/problem+json": { schema: ref("ProblemDetails") } } },
});
const conditionalFailures = { "412": problem("PreconditionFailed"), "428": problem("PreconditionRequired") };
const bodyFailures = { "413": responseRef("GroupPolicyBodyTooLarge"), "415": problem("ContentType") };
const baseDescription = "Require HTTPS, current Account/Device, active same-Organization Membership, actual-method/trusted-URL DPoP and durable replay protection. JWT snapshots and submitted role/group claims grant no authority. Inaccessible, foreign and absent resources share the static Organization 404 boundary. No refresh cookie is read or changed. ";
const mutationDescription = "Charge the existing independent durable team admission limits of 30 source and 10 authenticated-Account attempts per operation per 60 seconds. Recheck current authority and references under the committing transaction; row, membership associations, Organization view revision and one attributable audit commit atomically. Required audit failure rolls back mutation. ";
const receiptDescription = "One original UUIDv7 key binds origin, Account, Device, actual method/path, id and canonical typed payload for 24 hours. Changed payload or binding conflicts; used ids cannot be reused without the exact retained receipt. Exact replay rechecks current authority and returns the retained create Resource without another mutation or audit. ";

export function groupPolicyDefinitions() {
  const groupFields = object({ name, members }, true);
  const policyFields = object({ name, source: policySource, enabled: { type: "boolean" } }, true);
  const schemas = {
    GroupSource: { type: "string", enum: ["local", "IdP"], description: "Server-owned origin. This route creates only local groups; IdP groups are read-only here." },
    GroupFields: groupFields,
    GroupCreateRequest: { ...object({ id: uuid, data: ref("GroupFields") }, true), "x-scoplen-max-bytes": 262144 },
    GroupReplaceRequest: { ...object({ data: ref("GroupFields") }, true), "x-scoplen-max-bytes": 262144 },
    GroupResource: resource(object({ name, members, source: ref("GroupSource") })),
    GroupPage: page("GroupResource"),
    PolicyFields: policyFields,
    PolicyCreateRequest: { ...object({ id: uuid, data: ref("PolicyFields") }, true), "x-scoplen-max-bytes": 262144 },
    PolicyReplaceRequest: { ...object({ data: ref("PolicyFields") }, true), "x-scoplen-max-bytes": 262144 },
    PolicyResource: resource(object({ name, source: policySource, enabled: { type: "boolean" } })),
    PolicyPage: page("PolicyResource"),
    SimpleRuleSelector: object({ type: { type: "integer", enum: [1, 2, 4, 5, 6, 7, 11], description: "Known Organization K-1 inventory type only; no Credential, Forward or future type." }, id: uuid }, true),
    SimpleRuleConnect: { ...object({ hosts: ids(64, "Distinct Host ids; canonical encoders sort by UUID bytes."), host_groups: ids(64, "Distinct HostGroup ids; canonical encoders sort by UUID bytes."), remote_user: { type: "string", minLength: 1, maxLength: 255, "x-scoplen-max-utf8-bytes": 255, description: "Exact SSH remote username, no Unicode control characters; preserve without trimming or normalization." } }, true), anyOf: [{ properties: { hosts: { minItems: 1 } } }, { properties: { host_groups: { minItems: 1 } } }] },
    SimpleRuleInput: {
      oneOf: ["membership", "group"].flatMap(subject => ["view", "connect"].map(rule => object({ organization: uuid, [subject]: uuid, [rule]: rule === "view" ? { type: "array", minItems: 1, maxItems: 64, uniqueItems: true, items: ref("SimpleRuleSelector"), description: "Distinct typed selectors; canonical encoders sort by K-1 type then UUID bytes." } : ref("SimpleRuleConnect") }, true))),
      "x-scoplen-max-bytes": 262144,
      description: "Pure shared generator input, not an HTTP authorization operation. Exactly one current Membership or Group subject and one independent view or connect rule. Produce one <=65536 UTF-8-byte schema-valid permit scoped to this Organization, with canonical sorting and escaping. View matches only selected typed resources; connect matches selected Hosts/current HostGroup members plus exact remote_user. Never synthesize time, approval, roles, wildcard action/entity or dependency-read grants. Preview grants no authority; persist through the normal policy route.",
    },
    GroupPolicyBodyTooLargeProblem: { allOf: [ref("ProblemDetails"), { type: "object", properties: { status: { const: 413 }, code: { const: "organization.invalid_request" }, changed: { const: false }, retryable: { const: false } } }] },
  };
  const delay = "(?:[1-9]|[1-9][0-9]|[12][0-9]{2}|300)";
  const responses = {
    GroupResource: success("GroupResource", true), GroupPage: success("GroupPage", false),
    PolicyResource: success("PolicyResource", true), PolicyPage: success("PolicyPage", false),
    GroupPolicyBodyTooLarge: { description: "413 organization.invalid_request; changed=false/retryable=false. Complete problem <=4096 bytes.", headers, content: { "application/problem+json": { schema: ref("GroupPolicyBodyTooLargeProblem") } } },
    GroupPolicyRateLimited: { description: "Durable team-operation admission denied; changed=false/retryable=true. Retry-After is the greatest applicable wait rounded to 1..300 seconds, not an admission guarantee. Headers expose no private bucket.", headers: { "Retry-After": { required: true, schema: { type: "string", pattern: `^${delay}$` } }, "RateLimit-Policy": { required: true, schema: { const: '"authentication";q=30;w=60' } }, RateLimit: { required: true, schema: { type: "string", pattern: `^"authentication";r=0;t=${delay}$` }, description: "The t delay equals Retry-After." }, ...headers }, content: { "application/problem+json": { schema: ref("AuthRateLimitedProblem") } } },
  };
  const paths = {};
  for (const [plural, singular, readAuthority, writeScope, writeAction, specific] of [
    ["groups", "Group", { "x-scoplen-accepted-cedar-actions": ["view_policy", "manage_members"] }, "teams:manage", "manage_members", "Only local groups are mutable; source cannot be submitted. Every selected member is a currently active same-team Membership. Group updates cannot reactivate suspended or removed members. Deletion removes associations; a persisted policy referencing the Group prevents deletion with organization.conflict until updated or removed. "],
    ["policies", "Policy", { "x-scoplen-cedar-action": "view_policy" }, "policies:write", "manage_policy", "Exactly one schema-valid non-template policy with the initial context.now visibility restriction; validate every explicit typed reference against this Organization. Advanced policies need no explicit Organization literal, but any present literal must match the owner. Enabled custom policies are evaluated only with this team's immutable built-in roles and mandatory tenant guards. A policy cannot change those guards, elevate an Operator or authorize Personal/foreign data. "],
  ]) {
    const collection = `/orgs/{org}/${plural}`;
    const item = `${collection}/{id}`;
    paths[collection] = {
      get: {
        operationId: `listOrganization${singular}s`, "x-scoplen-required-device-scope": "policies:read", ...readAuthority, "x-scoplen-response-max-bytes": 8388608,
        description: `${baseDescription}Require policies:read and ${singular === "Group" ? "either view_policy or manage_members; this is not a public Account directory" : "view_policy"}. Return live ascending bounded Resources, not an atomic current-view sync. Reject body, duplicate/unknown query names, If-Match and Idempotency-Key.`,
        parameters: [orgParameter, ...pagination], responses: { "200": responseRef(`${singular}Page`), ...failures() },
      },
      post: {
        operationId: `createOrganization${singular}`, "x-scoplen-required-device-scope": writeScope, "x-scoplen-cedar-action": writeAction, "x-scoplen-request-max-bytes": 262144, "x-scoplen-response-max-bytes": 262144,
        description: `${baseDescription}${mutationDescription}${receiptDescription}${specific}Reject every query and If-Match.`,
        parameters: [orgParameter, idempotency], requestBody: request(`${singular}CreateRequest`),
        responses: { "201": responseRef(`${singular}Resource`), ...failures(true, true), ...bodyFailures },
      },
    };
    paths[item] = {
      get: {
        operationId: `getOrganization${singular}`, "x-scoplen-required-device-scope": "policies:read", ...readAuthority, "x-scoplen-response-max-bytes": 262144,
        description: `${baseDescription}Require policies:read and ${singular === "Group" ? "either view_policy or manage_members" : "view_policy"}. Bind returned id to the captured request. Reject body, every query, If-Match and Idempotency-Key.`,
        parameters: [orgParameter, idParameter], responses: { "200": responseRef(`${singular}Resource`), ...failures() },
      },
      put: {
        operationId: `replaceOrganization${singular}`, "x-scoplen-required-device-scope": writeScope, "x-scoplen-cedar-action": writeAction, "x-scoplen-request-max-bytes": 262144, "x-scoplen-response-max-bytes": 262144,
        description: `${baseDescription}${mutationDescription}${specific}Complete replacement, not a merge or hidden-field patch. Authorize before comparing exact original If-Match. Equal current fields are a no-op without a view revision or audit increment. Immutable id and Organization owner cannot change. Reject every query and Idempotency-Key.`,
        parameters: [orgParameter, idParameter, ifMatch], requestBody: request(`${singular}ReplaceRequest`),
        responses: { "200": responseRef(`${singular}Resource`), ...failures(true), ...bodyFailures, ...conditionalFailures },
      },
      delete: {
        operationId: `deleteOrganization${singular}`, "x-scoplen-required-device-scope": writeScope, "x-scoplen-cedar-action": writeAction,
        description: `${baseDescription}${mutationDescription}${specific}Authorize before comparing exact original If-Match. Reject body, every query and Idempotency-Key.`,
        parameters: [orgParameter, idParameter, ifMatch], responses: { "204": { description: "Deleted; no body.", headers }, ...failures(true), ...conditionalFailures },
      },
    };
  }
  for (const path of Object.values(paths)) {
    for (const operation of Object.values(path)) operation.security = [{ accessToken: [], dpopProof: [] }];
  }
  return { schemas, responses, paths };
}

export function generateGroupPolicyTypes(document) {
  const expected = groupPolicyDefinitions();
  for (const [section, values] of Object.entries(expected)) {
    const actual = section === "paths" ? document.paths : document.components?.[section];
    for (const [name, value] of Object.entries(values)) {
      if (!isDeepStrictEqual(actual?.[name], value)) throw new Error(`D-137 ${section}.${name} differs from its exact group/policy contract`);
    }
  }
  return [
    'export type GroupSource = "local" | "IdP";',
    "export interface GroupFields { name: string; members: string[]; }",
    "export interface GroupCreateRequest { id: string; data: GroupFields; }",
    "export interface GroupReplaceRequest { data: GroupFields; }",
    "export interface GroupResource {",
    "  id: string; etag: string; created_at: string; updated_at: string;",
    "  data: GroupFields & { source: GroupSource; [extension: string]: unknown };",
    "  [extension: string]: unknown;", "}",
    "export interface GroupPage { items: GroupResource[]; next_cursor: string | null; [extension: string]: unknown; }",
    "export interface PolicyFields { name: string; source: string; enabled: boolean; }",
    "export interface PolicyCreateRequest { id: string; data: PolicyFields; }",
    "export interface PolicyReplaceRequest { data: PolicyFields; }",
    "export interface PolicyResource {",
    "  id: string; etag: string; created_at: string; updated_at: string;",
    "  data: PolicyFields & { [extension: string]: unknown };",
    "  [extension: string]: unknown;", "}",
    "export interface PolicyPage { items: PolicyResource[]; next_cursor: string | null; [extension: string]: unknown; }",
    "export interface SimpleRuleSelector { type: 1 | 2 | 4 | 5 | 6 | 7 | 11; id: string; }",
    "export interface SimpleRuleConnect { hosts: string[]; host_groups: string[]; remote_user: string; }",
    "export type SimpleRuleSubject = { membership: string; group?: never } | { group: string; membership?: never };",
    "export type SimpleRule = { view: SimpleRuleSelector[]; connect?: never } | { connect: SimpleRuleConnect; view?: never };",
    "/** Pure preview input; use the shared native generator and persist through the authorized policy route. */",
    "export type SimpleRuleInput = { organization: string } & SimpleRuleSubject & SimpleRule;",
    'export type GroupPolicyBodyTooLargeProblem = ProblemDetails & { status: 413; code: "organization.invalid_request"; changed: false; retryable: false; };', "",
  ].join("\n");
}
