// SPDX-License-Identifier: Apache-2.0
import { isDeepStrictEqual } from "node:util";
import { header, headers, issuer, key, object, org, response, schema, tag, time, uuid } from "./generate-auth-connection-draft.mjs";

const root = "/orgs/{org}/auth-link";
const attempts = root + "/attempts";
const named = "/orgs/{org}/members/{membership}/auth-link";
const attempt = { name: "attempt", in: "path", required: true, schema: uuid };
const membership = { name: "membership", in: "path", required: true, schema: uuid };
const origin = header("Origin", { type: "string", format: "uri", description: "Exact trusted browser Origin." });
const readOrigin = { ...origin, required: false };
const ifMatch = header("If-Match", tag);
const freshness = { "x-scoplen-original-password-max-age-seconds": 300 };
const profiles = {
  self: { "x-scoplen-required-browser-scope": "auth-links:self" },
  withdraw: {
    "x-scoplen-required-browser-scope": "auth-links:withdraw",
    "x-scoplen-required-membership-roles-any": ["owner"],
    "x-scoplen-cedar-action": "manage_members",
  },
};

const errors = {
  400: response("OrganizationInvalidRequest"), 401: response("OrganizationAuthenticationRequired"),
  403: response("OrganizationDenied"), 404: response("OrganizationNotFound"), 429: response("GroupPolicyRateLimited"),
  503: response("OrganizationStorageUnavailable"),
  default: { description: "Bounded problem without membership link or provider data.", headers,
    content: { "application/problem+json": { schema: schema("ProblemDetails") } } },
};
const conditions = { 412: response("OrganizationPreconditionFailed"), 428: response("OrganizationPreconditionRequired") };
const conflict = { 409: response("OrganizationConflict") };
const unavailable = (kind, description) => ({
  description, headers, content: { "application/problem+json": {
    schema: { oneOf: ["OrganizationStorageUnavailableProblem", kind].map(schema) },
  } },
});
const noReceipt = unavailable("OrganizationUpdateCommitOutcomeUnknownProblem", "Unconfirmed write. Read current state or let the unknown attempt expire.");
const withReceipt = unavailable("OrganizationCommitOutcomeUnknownProblem", "Recover only through the eligible original writer receipt.");
const json = (name, description, responseHeaders = headers) => ({
  description, headers: responseHeaders, content: { "application/json": { schema: schema(name) } },
});
const empty = description => ({ description, headers });
const cookie = {
  required: true, schema: { type: "string" },
  description: "__Host-spl-auth-link-<state_digest>, using lowercase hex SHA-256 of the 32 decoded state bytes. Path=/; HttpOnly; Secure; SameSite=Lax; no Domain. Expiry is bounded by the attempt.",
};
const confidential = ["sub", "subject", "subject_digest", "subject_comparison", "comparison_value", "claims", "client_secret", "access_token", "refresh_token", "id_token"];
function publicObject(fields, { allowNavigation = false, excluded = [] } = {}) {
  const forbidden = [...confidential, ...excluded];
  if (!allowNavigation) forbidden.push("authorization_url");
  return { ...object(fields, true), "x-scoplen-max-bytes": 8192,
    not: { anyOf: forbidden.map(name => ({ required: [name] })) } };
}
const context = { organization_id: uuid, membership_id: uuid };
const status = { ...context, link: { anyOf: [schema("OrganizationMemberLink"), { type: "null" }] } };
const attemptFields = { ...context, id: uuid, connection_revision: uuid, expires_at: time };
const protectedRequest = "Require a live Account-browser family, exact request DPoP and active current membership. Recheck authority in the state transaction before protected lookups. No body, Content-Type or query. ";
function operation(actor, operationId, description, parameters, responses, options = {}) {
  return {
    security: [{ accountBrowserAccess: [], dpopProof: [] }],
    ...profiles[actor],
    "x-scoplen-fetch-credentials": "omit",
    "x-scoplen-request-max-bytes": 0,
    "x-scoplen-response-max-bytes": responses[204] ? 0 : 8192,
    "x-scoplen-problem-max-bytes": 4096,
    ...options, operationId, description: protectedRequest + description, parameters, responses: { ...errors, ...responses },
  };
}

export function memberLinkDefinitions() {
  const schemas = {
    OrganizationMemberLink: publicObject({ id: uuid, etag: tag, created_at: time, ...context }),
    OrganizationLinkConnection: publicObject({ id: uuid, etag: tag,
      issuer: { ...issuer, description: "Exact HTTPS issuer bound to the active connection." },
      client_id: { type: "string", minLength: 1, maxLength: 512, "x-scoplen-max-utf8-bytes": 512, pattern: "^[^\\u0000-\\u001f\\u007f-\\u009f]+$" },
      space_id: { type: "string", pattern: "^spc_[A-Za-z0-9_-]{1,92}$", minLength: 5, maxLength: 96 },
    }),
    OrganizationMemberLinkStatus: publicObject(status, { excluded: ["connection"] }),
    OrganizationSelfLinkStatus: publicObject({ ...status,
      connection: { anyOf: [schema("OrganizationLinkConnection"), { type: "null" }] },
    }),
    OrganizationLinkAttempt: publicObject({
      ...attemptFields, status: { type: "string", enum: ["pending", "verified", "failed"] },
    }),
    OrganizationLinkAttemptStarted: publicObject({
      ...attemptFields, status: { type: "string", const: "pending" },
      authorization_url: { type: "string", format: "uri", pattern: "^[Hh][Tt][Tt][Pp][Ss]://" },
    }, { allowNavigation: true }),
  };
  const paths = {
    [root]: {
      get: operation("self", "getOrganizationSelfAuthLink",
        "Read the current Account's Membership link and active revision. Validate Origin when supplied.",
        [org, readOrigin], { 200: json("OrganizationSelfLinkStatus", "Current self status.") }),
      delete: operation("self", "unlinkOrganizationSelfAuthLink",
        "Unlink the reviewed association and invalidate its external evidence in an audited transaction.",
        [org, origin, ifMatch], { ...conditions, 204: empty("Association withdrawn. Empty body."), 503: noReceipt }),
    },
    [attempts]: { post: operation("self", "startOrganizationAuthLinkAttempt",
      "Resolve the caller's own active Membership and original recent password proof. Pin the active revision and link generation. Construct navigation without provider egress. A lost start is never replayed.",
      [org, origin, ifMatch], { ...conditions, ...conflict,
        201: json("OrganizationLinkAttemptStarted", "Pending attempt and one-time provider navigation.", { ...headers, "Set-Cookie": cookie }),
        503: noReceipt,
      }, { ...freshness, "x-scoplen-fetch-credentials": "same-origin" }) },
    [attempts + "/{attempt}"]: {
      get: operation("self", "getOrganizationAuthLinkAttempt",
        "Read the original family's attempt. A claimed exchange reads as pending. Validate Origin when supplied.",
        [org, attempt, readOrigin], { 200: json("OrganizationLinkAttempt", "Original attempt status.") }),
      delete: operation("self", "abandonOrganizationAuthLinkAttempt",
        "Abandon the original family's attempt, including during exchange.",
        [org, attempt, origin], { 204: empty("Attempt abandoned. Empty body."), 503: noReceipt }),
    },
    [attempts + "/{attempt}/confirm"]: { post: operation("self", "confirmOrganizationAuthLinkAttempt",
      "Confirm one verified human subject in the original eligible family and active revision. Bind the original request to a 24-hour writer receipt.",
      [org, attempt, origin, ifMatch, key], { ...conditions, ...conflict,
        201: json("OrganizationMemberLink", "Original immutable link. HTTP and body ETags quote its ID.", { ...headers, ETag: { required: true, schema: tag } }),
        503: withReceipt,
      }, freshness) },
    [named]: {
      get: operation("withdraw", "getOrganizationNamedMemberAuthLink",
        "Only an authorized Owner may inspect the named current Membership's public link. Validate Origin when supplied.",
        [org, membership, readOrigin], { 200: json("OrganizationMemberLinkStatus", "Current named-member status.") }),
      delete: operation("withdraw", "withdrawOrganizationNamedMemberAuthLink",
        "Only an authorized Owner may withdraw the named current Membership's reviewed link.",
        [org, membership, origin, ifMatch], { ...conditions, 204: empty("Association withdrawn. Empty body."), 503: noReceipt }),
    },
  };
  return { schemas, paths };
}

export function memberLinkBrowserOperations() {
  return Object.entries(memberLinkDefinitions().paths).flatMap(([path, operations]) =>
    Object.entries(operations).map(([method, operation]) => ({
      method: method.toUpperCase(), path: "/api/v1" + path,
      scopes: [operation["x-scoplen-required-browser-scope"]],
      writerReceipt: operation.parameters.some(parameter => parameter.name === "Idempotency-Key"),
    })),
  );
}

export function generateMemberLinkTypes(document) {
  const expected = memberLinkDefinitions();
  const actual = Object.keys(document.paths).filter(path => path === root || path.startsWith(root + "/") || path === named);
  if (!isDeepStrictEqual(actual.sort(), Object.keys(expected.paths).sort())) throw new Error("D-170 path set drift");
  for (const [name, value] of Object.entries(expected.schemas)) {
    if (!isDeepStrictEqual(document.components.schemas[name], value)) throw new Error(`D-170 schema drift: ${name}`);
  }
  for (const [path, value] of Object.entries(expected.paths)) {
    if (!isDeepStrictEqual(document.paths[path], value)) throw new Error(`D-170 operation drift: ${path}`);
  }
  return `interface PublicLinkFields {
  sub?: never; subject?: never; subject_digest?: never; subject_comparison?: never;
  comparison_value?: never; claims?: never; client_secret?: never; access_token?: never;
  refresh_token?: never; id_token?: never;
  [extension: string]: unknown;
}
interface OrganizationLinkContext extends PublicLinkFields {
  organization_id: string; membership_id: string;
}
export interface OrganizationMemberLink extends OrganizationLinkContext {
  id: string; etag: string; created_at: string; authorization_url?: never;
}
export interface OrganizationLinkConnection extends PublicLinkFields {
  id: string; etag: string; issuer: string; client_id: string; space_id: string; authorization_url?: never;
}
interface OrganizationLinkStatusFields extends OrganizationLinkContext {
  link: OrganizationMemberLink | null; authorization_url?: never;
}
export interface OrganizationMemberLinkStatus extends OrganizationLinkStatusFields {
  connection?: never;
}
export interface OrganizationSelfLinkStatus extends OrganizationLinkStatusFields {
  connection: OrganizationLinkConnection | null;
}
interface OrganizationLinkAttemptFields extends OrganizationLinkContext {
  id: string; connection_revision: string; expires_at: string;
}
export interface OrganizationLinkAttempt extends OrganizationLinkAttemptFields {
  status: "pending" | "verified" | "failed"; authorization_url?: never;
}
export interface OrganizationLinkAttemptStarted extends OrganizationLinkAttemptFields {
  status: "pending"; authorization_url: string;
}
`;
}
