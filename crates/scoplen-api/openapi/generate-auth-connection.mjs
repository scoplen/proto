// SPDX-License-Identifier: Apache-2.0
import { isDeepStrictEqual } from "node:util";
import { header, headers, issuer, key, object, org, response, schema, tag, time, uuid } from "./generate-auth-connection-draft.mjs";

const root = "/orgs/{org}/auth-connection";
const attempts = root + "/activations";
const attempt = { name: "attempt", in: "path", required: true, schema: uuid };
const origin = header("Origin", { type: "string", format: "uri", description: "Exact trusted browser Origin." });
const ifMatch = header("If-Match", tag);
const condition = [
  { ...header("If-None-Match", { type: "string", const: "*" }), required: false },
  { ...ifMatch, required: false },
];
const expectedHead = {
  "x-scoplen-exactly-one-header": ["If-None-Match", "If-Match"],
};
const requiresFreshPassword = { "x-scoplen-original-password-max-age-seconds": 300 };
const profile = {
  security: [{ accountBrowserAccess: [], dpopProof: [] }],
  "x-scoplen-required-browser-scope": "auth-connection:manage",
  "x-scoplen-required-membership-roles-any": ["owner"],
  "x-scoplen-cedar-action": "manage_organization",
  "x-scoplen-fetch-credentials": "omit",
  "x-scoplen-request-max-bytes": 0,
  "x-scoplen-response-max-bytes": 8192,
  "x-scoplen-problem-max-bytes": 4096,
};
const issuerURL = { ...issuer, description: "Exact approved HTTPS issuer, including its path and trailing slash." };
const clientID = { type: "string", minLength: 1, maxLength: 512, "x-scoplen-max-utf8-bytes": 512, pattern: "^[^\\u0000-\\u001f\\u007f-\\u009f]+$" };
const spaceID = { type: "string", pattern: "^spc_[A-Za-z0-9_-]{1,92}$", minLength: 5, maxLength: 96 };
const privateFields = ["client_secret", "access_token", "refresh_token", "id_token", "claims"];
function publicObject(fields, forbidden) {
  return { ...object(fields, true), not: { anyOf: forbidden.map(name => ({ required: [name] })) } };
}
const activation = {
  id: uuid, organization_id: uuid, draft_generation: uuid, expected_revision: { anyOf: [uuid, { type: "null" }] },
  issuer: issuerURL, client_id: clientID, space_id: spaceID,
  status: { type: "string", enum: ["pending", "verified", "failed"] }, expires_at: time,
};
const json = (name, description, responseHeaders = headers) => ({
  description, headers: responseHeaders, content: { "application/json": { schema: schema(name) } },
});
const revision = name => json(name, "Immutable revision. HTTP and body ETags both quote its id. Both timestamps equal revision creation time.", {
  ...headers, ETag: { required: true, schema: tag },
});
const correlation = {
  required: true, schema: { type: "string" },
  description: "__Host-spl-auth-activate-<state_digest>, using lowercase hex SHA-256 of the 32 decoded state bytes. Path=/; HttpOnly; Secure; SameSite=Lax; no Domain. Its expiry is bounded by the attempt.",
};
const errors = {
  400: response("OrganizationInvalidRequest"), 401: response("OrganizationAuthenticationRequired"),
  403: response("OrganizationDenied"), 404: response("OrganizationNotFound"), 429: response("GroupPolicyRateLimited"),
  503: response("OrganizationStorageUnavailable"),
  default: { description: "Bounded Organization problem without connection data.", headers, content: { "application/problem+json": { schema: schema("ProblemDetails") } } },
};
const conditionErrors = {
  409: response("OrganizationConflict"), 412: response("OrganizationPreconditionFailed"), 428: response("OrganizationPreconditionRequired"),
};
const storageFailure = (description, variants) => ({
  description, headers, content: { "application/problem+json": { schema: { oneOf: variants.map(schema) } } },
});
const transitionFailure = storageFailure("On an uncertain commit use only the 24-hour original writer receipt.", ["OrganizationStorageUnavailableProblem", "OrganizationCommitOutcomeUnknownProblem"]);
const startFailure = storageFailure("Rollback, provider failure or unconfirmed start. No navigation or cookie is issued.", [
  "OrganizationStorageUnavailableProblem", "OrganizationAuthProviderUnavailableProblem", "OrganizationUpdateCommitOutcomeUnknownProblem",
]);
const abandonFailure = storageFailure("A failed or unconfirmed abandonment grants no authority.", ["OrganizationStorageUnavailableProblem", "OrganizationUpdateCommitOutcomeUnknownProblem"]);
const authority = "Require a live Account-browser family, DPoP for the actual request, current Owner membership and Cedar manage_organization. Recheck before examining any slot, attempt or receipt. No query parameters. ";
const head = "Send exactly one If-None-Match: * for an empty slot or a strong If-Match for the quoted current revision. ";

export function authConnectionDefinitions() {
  const schemas = {
    AuthConnectionCandidate: {
      ...object({ draft_generation: uuid, client_id: clientID, client_secret: { ...clientID, writeOnly: true }, space_id: spaceID }, false),
      "x-scoplen-max-bytes": 4096,
    },
    AuthConnectionResource: {
      ...publicObject({ id: uuid, etag: tag, created_at: time, updated_at: time, data: publicObject({
        organization_id: uuid, status: { type: "string", enum: ["active", "suspended"] }, issuer: issuerURL, client_id: clientID, space_id: spaceID,
      }, [...privateFields, "authorization_url"]) }, [...privateFields, "authorization_url"]),
      "x-scoplen-max-bytes": 8192,
    },
    AuthConnectionActiveResource: {
      allOf: [schema("AuthConnectionResource"), { properties: { data: { properties: { status: { const: "active" } } } } }],
    },
    AuthConnectionSuspendedResource: {
      allOf: [schema("AuthConnectionResource"), { properties: { data: { properties: { status: { const: "suspended" } } } } }],
    },
    AuthConnectionActivation: {
      ...publicObject(activation, [...privateFields, "authorization_url"]), "x-scoplen-max-bytes": 8192,
    },
    AuthConnectionActivationStarted: {
      ...publicObject({ ...activation, status: { type: "string", const: "pending" }, authorization_url: {
        type: "string", format: "uri", pattern: "^[Hh][Tt][Tt][Pp][Ss]://", description: "One-time navigation at the approved provider origin.",
      } }, privateFields), "x-scoplen-max-bytes": 8192,
    },
  };
  const paths = {
    [root]: { get: {
      ...profile, operationId: "getOrganizationAuthConnection", parameters: [org, { ...origin, required: false }],
      description: authority + "Read the current revision; an empty slot returns 404. Validate Origin when supplied.",
      responses: { ...errors, 200: revision("AuthConnectionResource") },
    } },
    [attempts]: { post: {
      ...profile, ...expectedHead, ...requiresFreshPassword, operationId: "startOrganizationAuthConnectionActivation",
      "x-scoplen-fetch-credentials": "same-origin", "x-scoplen-request-max-bytes": 4096,
      parameters: [org, origin, ...condition],
      description: authority + head + "Require the original family's recent password authentication at start and commit. Check the selected draft and current head before issuer contact. A lost start must not be replayed.",
      requestBody: { required: true, content: { "application/json": { schema: schema("AuthConnectionCandidate") } } },
      responses: { ...errors, ...conditionErrors, 201: json("AuthConnectionActivationStarted", "Pending activation with its one-time authorization URL.", { ...headers, "Set-Cookie": correlation }),
        413: response("GrantBodyTooLarge"), 415: response("OrganizationContentType"), 503: startFailure },
    } },
    [attempts + "/{attempt}"]: {
      get: {
        ...profile, operationId: "getOrganizationAuthConnectionActivation", parameters: [org, attempt, { ...origin, required: false }],
        description: authority + "Read the original family's current attempt. A claimed exchange remains pending. Validate Origin when supplied.",
        responses: { ...errors, 200: json("AuthConnectionActivation", "Attempt status in the original browser family.") },
      },
      delete: {
        ...profile, operationId: "abandonOrganizationAuthConnectionActivation", "x-scoplen-response-max-bytes": 0, parameters: [org, attempt, origin],
        description: authority + "Abandon the original family's attempt and retire the proposed credential, including during exchange.",
        responses: { ...errors, 204: { description: "Attempt abandoned. Empty body.", headers }, 503: abandonFailure },
      },
    },
    [attempts + "/{attempt}/confirm"]: { post: {
      ...profile, ...expectedHead, ...requiresFreshPassword, operationId: "confirmOrganizationAuthConnectionActivation", parameters: [org, attempt, origin, key, ...condition],
      description: authority + head + "Confirm the verified, unexpired candidate in its original fresh family. Bind the exact request to a 24-hour writer receipt.",
      responses: { ...errors, ...conditionErrors, 200: revision("AuthConnectionActiveResource"), 503: transitionFailure },
    } },
    [root + "/suspend"]: { post: {
      ...profile, operationId: "suspendOrganizationAuthConnection", parameters: [org, origin, key, ifMatch],
      description: authority + "Suspend the active revision locally. Verify the exact original writer and intent on receipt confirmation.",
      responses: { ...errors, ...conditionErrors, 200: revision("AuthConnectionSuspendedResource"), 503: transitionFailure },
    } },
  };
  return { schemas, paths };
}

export function generateAuthConnectionTypes(document) {
  const expected = authConnectionDefinitions();
  const connectionPaths = Object.keys(document.paths).filter(path => path === root || path.startsWith(root + "/"));
  if (!isDeepStrictEqual(connectionPaths.sort(), Object.keys(expected.paths).sort())) throw new Error("D-169 path set drift");
  for (const [name, value] of Object.entries(expected.schemas)) {
    if (!isDeepStrictEqual(document.components.schemas[name], value)) throw new Error(`D-169 schema drift: ${name}`);
  }
  for (const [path, value] of Object.entries(expected.paths)) {
    if (!isDeepStrictEqual(document.paths[path], value)) throw new Error(`D-169 operation drift: ${path}`);
  }
  return `export interface AuthConnectionCandidate {
  draft_generation: string; client_id: string; client_secret: string; space_id: string;
}
export type AuthConnectionCondition =
  | { "If-None-Match": "*"; "If-Match"?: never }
  | { "If-Match": string; "If-None-Match"?: never };
interface PublicConnectionFields {
  client_secret?: never; access_token?: never; refresh_token?: never; id_token?: never; claims?: never;
  [extension: string]: unknown;
}
export interface AuthConnectionResource extends PublicConnectionFields {
  id: string; etag: string; created_at: string; updated_at: string; authorization_url?: never;
  data: PublicConnectionFields & {
    organization_id: string; status: "active" | "suspended"; issuer: string; client_id: string; space_id: string;
    authorization_url?: never;
  };
}
export type AuthConnectionActiveResource = AuthConnectionResource & { data: { status: "active" } };
export type AuthConnectionSuspendedResource = AuthConnectionResource & { data: { status: "suspended" } };
interface ActivationFields extends PublicConnectionFields {
  id: string; organization_id: string; draft_generation: string; expected_revision: string | null;
  issuer: string; client_id: string; space_id: string; expires_at: string;
}
export interface AuthConnectionActivation extends ActivationFields {
  status: "pending" | "verified" | "failed"; authorization_url?: never;
}
export interface AuthConnectionActivationStarted extends ActivationFields {
  status: "pending"; authorization_url: string;
}
`;
}
