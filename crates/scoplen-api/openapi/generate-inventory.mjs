// SPDX-License-Identifier: Apache-2.0
// D-137 named, clock-free Organization inventory contracts.
import { isDeepStrictEqual } from "node:util";

const ref = name => ({ $ref: `#/components/schemas/${name}` });
const uuid = { type: "string", format: "uuid", pattern: "^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$" };
const text = { type: "string", maxLength: 16384, "x-scoplen-max-utf8-bytes": 16384, description: "NFC text; preserve valid whitespace, never trim or normalize. All K-1 text and complete-object limits still apply." };
const integer = (minimum, maximum) => ({ type: "integer", minimum, maximum, "x-scoplen-integer-token": true, description: "An exact JSON integer token, without decimal or exponent aliases." });
const object = (properties, required = Object.keys(properties), extensions = false) => ({ type: "object", additionalProperties: extensions, required, properties });
const map = (value, key = text) => ({ type: "object", maxProperties: 4096, propertyNames: key, additionalProperties: value });
const timestamp = { type: "string", format: "date-time", pattern: "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-5][0-9](\\.[0-9]+)?Z$", description: "A valid UTC calendar timestamp." };
const etag = { type: "string", pattern: '^"[!#-~]*"$', minLength: 2, maxLength: 256 };
const headers = {
  "Cache-Control": { required: true, schema: { type: "string", const: "no-store" } },
  Pragma: { required: true, schema: { type: "string", const: "no-cache" } },
  "X-Request-ID": { required: true, schema: { type: "string", minLength: 1 } },
};
const org = { name: "org", in: "path", required: true, schema: uuid };
const id = { name: "id", in: "path", required: true, schema: uuid };
const key = { name: "Idempotency-Key", in: "header", required: true, schema: uuid };
const match = { name: "If-Match", in: "header", required: true, description: "Exactly one original strong ETag; no weak, wildcard or multiple values and no silent replacement/replay.", schema: etag };
const pagination = [
  { name: "limit", in: "query", required: false, schema: { type: "integer", minimum: 1, maximum: 500, default: 50 } },
  { name: "cursor", in: "query", required: false, schema: uuid },
];
const kinds = [
  ["Host", "hosts", 1], ["AccessProfile", "access-profiles", 2], ["Route", "routes", 4],
  ["HostGroup", "host-groups", 5], ["TrustRecord", "trust-records", 6],
  ["Snippet", "snippets", 7], ["GatewayNetwork", "gateway-networks", 11],
];
const base = "Require HTTPS, current Account/Device, trusted actual-method/URL DPoP, replay protection and current active same-Organization Membership. JWT snapshots and a supplied Organization id confer no authority. No refresh cookie is read or changed. Missing, foreign and unreadable targets share the same not-found boundary. ";
const mutation = "Recheck current authorization and every declared reference's type, same-team ownership and independent read permission in the committing transaction. Atomically write canonical K-1 with server clocks/current Device origins, sequence, checked positive view revision and one attributable audit; publish notifications only after commit. Mandatory audit failure rolls back. No Personal Credential fallback, Organization Credential, proxy secret or caller field clock. ";

export function inventoryDefinitions() {
  const schemas = {
    InventorySnippetVariable: { oneOf: [
      object({ kind: { ...integer(1, 1), const: 1 }, default: text }, ["kind"]),
      object({ kind: { ...integer(2, 2), const: 2 }, default: { type: "string", pattern: "^(0|-?[1-9][0-9]*)$", maxLength: 20, description: "Canonical signed 64-bit decimal, -9223372036854775808 through 9223372036854775807." } }, ["kind"]),
      { ...object({ kind: { ...integer(3, 3), const: 3 }, default: text, choices: { type: "array", minItems: 1, maxItems: 4096, uniqueItems: true, items: text } }, ["kind", "choices"]), description: "An optional default must occur in choices; preserve choice order." },
      object({ kind: { ...integer(4, 4), const: 4 } }),
    ] },
    InventoryBodyTooLargeProblem: { allOf: [ref("ProblemDetails"), { type: "object", properties: { status: { const: 413 }, code: { const: "organization.invalid_request" }, changed: { const: false }, retryable: { const: false } } }] },
  };
  const fields = {
    Host: object({ name: text, address: text, port: integer(1, 65535), tags: map(text), groups: map({ const: true }, uuid), favorite: { type: "boolean" }, notes: text, default_profile: uuid, ssh_options: map(text), mosh: map(text) }, ["name", "address"]),
    AccessProfile: object({ host: uuid, name: text, username: text, route: { oneOf: [uuid, { type: "integer", const: 0, "x-scoplen-integer-token": true }] }, terminal_profile: text, startup_command: text, agent_forwarding: { type: "boolean" } }, ["host", "username"]),
    Route: { oneOf: [
      object({ name: text, kind: { ...integer(1, 1), const: 1 }, hops: { type: "array", items: uuid } }),
      object({ name: text, kind: { ...integer(2, 2), const: 2 }, proxy: text }),
      object({ name: text, kind: { ...integer(3, 3), const: 3 }, proxy: text }),
      object({ name: text, kind: { ...integer(4, 4), const: 4 }, command: text }),
      object({ name: text, kind: { ...integer(5, 5), const: 5 }, gateway_network: uuid }),
    ], description: "Exact integer kind 1..5. Proxy credentials are unavailable in Organization inventory, so paired proxy_username is also absent. Route cycles and native command confirmation remain consumer checks." },
    HostGroup: object({ name: text, parent: uuid, color: text, defaults: { ...map(text), propertyNames: { ...text, not: { const: "credential" } }, description: "No credential default. Non-direct route values are canonical Route UUIDv7 locators and require independent same-team authorization." } }, ["name"]),
    TrustRecord: { ...object({ host: uuid, pattern: text, key: text, fingerprint: text, provenance: integer(1, 4), revoked: { type: "boolean" }, ca: { type: "boolean" } }, []), anyOf: [{ required: ["host"] }, { required: ["pattern"] }], dependentRequired: { fingerprint: ["key"] }, description: "Validate OpenSSH public key and matching SHA-256 fingerprint. Attribution is forbidden on write." },
    Snippet: object({ name: text, template: text, variables: map(ref("InventorySnippetVariable")), tags: map({ const: true }), folder: text }, ["name", "template"]),
    GatewayNetwork: object({ name: text, description: text }, []),
  };
  const responses = {
    InventoryBodyTooLarge: { description: "413 organization.invalid_request; changed=false, retryable=false. No partial success body.", headers, content: { "application/problem+json": { schema: ref("InventoryBodyTooLargeProblem") } } },
  };
  const problem = suffix => ({ $ref: `#/components/responses/Organization${suffix}` });
  const failure = write => ({
    "400": problem("InvalidRequest"), "401": problem("AuthenticationRequired"), "403": problem("Denied"),
    "404": problem("NotFound"), "409": problem("Conflict"),
    ...(write ? { "412": problem("PreconditionFailed"), "413": { $ref: "#/components/responses/InventoryBodyTooLarge" }, "415": problem("ContentType"), "428": problem("PreconditionRequired") } : {}),
    "503": problem("StorageUnavailable"),
    default: { description: "Bounded shared problem <=4096 bytes; retain auth/admission status and retry headers. Never send a partial Resource or Page.", headers, content: { "application/problem+json": { schema: ref("ProblemDetails") } } },
  });
  const response = (name, individual) => ({ description: individual ? "Complete typed Resource <=2097152 bytes; header ETag exactly equals body etag." : "Complete Page <=8388608 bytes, at most 500 Resources; each original item <=2097152 bytes including extensions and whitespace. Live ascending distinct authorized ids beyond cursor, with a shorter prefix when the body budget requires it.", headers: { ...headers, ...(individual ? { ETag: { required: true, schema: etag } } : {}) }, content: { "application/json": { schema: ref(name) } } });
  const storage = create => ({ description: create ? "Confirmed rollback is changed=false/retryable=true. Unconfirmed COMMIT is changed=true/retryable=true: explicitly replay only original key/payload within its original 24 hours, using fresh DPoP." : "Confirmed rollback is changed=false/retryable=true. Unconfirmed COMMIT is changed=true/retryable=false: refresh/review, never replay or substitute If-Match.", headers, content: { "application/problem+json": { schema: { oneOf: [ref("OrganizationStorageUnavailableProblem"), ref(create ? "OrganizationCommitOutcomeUnknownProblem" : "OrganizationUpdateCommitOutcomeUnknownProblem")] } } } });
  const paths = {};
  for (const [name, segment, type] of kinds) {
    const prefix = `Inventory${name}`;
    schemas[`${prefix}Fields`] = { ...fields[name], "x-scoplen-k1-type": type, "x-scoplen-k1-max-bytes": 262144 };
    const readFields = structuredClone(schemas[`${prefix}Fields`]);
    if (name === "TrustRecord") {
      Object.assign(readFields.properties, { accepted_at: { type: "string", pattern: "^(0|[1-9][0-9]*)$", maxLength: 20, description: "Canonical uint64 Unix milliseconds, at most 18446744073709551615; server-assigned." }, accepted_by_device: { ...uuid, readOnly: true }, accepted_by_account: { ...uuid, readOnly: true } });
      readFields.properties.accepted_at.readOnly = true;
      readFields.required.push("accepted_at", "accepted_by_device", "accepted_by_account");
    }
    schemas[`${prefix}ReadFields`] = readFields;
    schemas[`${prefix}CreateRequest`] = { ...object({ id: uuid, data: object({ fields: ref(`${prefix}Fields`) }) }), "x-scoplen-max-bytes": 2097152 };
    schemas[`${prefix}ReplaceRequest`] = { ...object({ data: object({ fields: ref(`${prefix}Fields`) }) }), "x-scoplen-max-bytes": 2097152 };
    schemas[`${prefix}Resource`] = { ...object({ id: uuid, etag, created_at: timestamp, updated_at: timestamp, data: object({ schema: { type: "integer", const: 1, "x-scoplen-integer-token": true }, fields: ref(`${prefix}ReadFields`) }, ["schema", "fields"], true) }, undefined, true), "x-scoplen-max-bytes": 2097152 };
    schemas[`${prefix}Page`] = { ...object({ items: { type: "array", maxItems: 500, items: ref(`${prefix}Resource`) }, next_cursor: { anyOf: [uuid, { type: "null" }], description: "Non-null only when more eligible items exist; equals the last id of a nonempty page." } }, undefined, true), "x-scoplen-max-bytes": 8388608 };
    const read = (suffix, parameters) => ({ operationId: `${suffix === "Page" ? "list" : "get"}${prefix}`, security: [{ accessToken: [], dpopProof: [] }], "x-scoplen-required-device-scope": "inventory:read", "x-scoplen-cedar-action": "view_inventory", "x-scoplen-response-max-bytes": suffix === "Page" ? 8388608 : 2097152, description: base + "Evaluate view_inventory independently for every returned object. Return full authorized typed fields with opaque locators, never hydrate hidden dependencies. Reject body, If-Match, Idempotency-Key and unknown/duplicate query names.", parameters, responses: { "200": response(`${prefix}${suffix}`, suffix === "Resource"), ...failure(false) } });
    const write = (method, parameters) => ({ operationId: `${method === "post" ? "create" : method === "put" ? "replace" : "delete"}${prefix}`, security: [{ accessToken: [], dpopProof: [] }], "x-scoplen-required-device-scope": "inventory:write", "x-scoplen-cedar-action": "manage_inventory", ...(method === "delete" ? {} : { "x-scoplen-request-max-bytes": 2097152, "x-scoplen-response-max-bytes": 2097152 }), description: base + mutation + (method === "post" ? "One UUIDv7 Idempotency-Key binds origin/Account/Device/method/path/id/canonical typed payload for 24 hours. Exact replay rechecks current authority and returns the retained create Resource, without another mutation; changed binding or used id conflicts. Reject every query and If-Match." : "Require object read permission and one original If-Match, compared after authorization; missing is 428, stale is 412. Reject every query and Idempotency-Key. " + (method === "put" ? "Complete desired mutable fields, never a field-clock merge or hidden-field patch; equal fields are a no-op with no sequence/revision/audit increment." : "Reject body; create the canonical K-1 tombstone. An active reference prevents deletion; remove/update references first.")), parameters, ...(method === "delete" ? {} : { requestBody: { required: true, description: "Complete JSON <=2097152 bytes; strict duplicate/unknown request keys recursively; typed NFC model fields, no null, clocks, binary or unsupported schema. Enforce actual complete K-1 size <=262144 bytes with committing clocks.", content: { "application/json": { schema: ref(`${prefix}${method === "post" ? "Create" : "Replace"}Request`) } } } }), responses: { [method === "post" ? "201" : method === "put" ? "200" : "204"]: method === "delete" ? { description: "Committed canonical K-1 tombstone; no body.", headers } : response(`${prefix}Resource`, true), ...failure(true), "503": storage(method === "post") } });
    paths[`/orgs/{org}/${segment}`] = { get: read("Page", [org, ...pagination]), post: write("post", [org, key]) };
    delete paths[`/orgs/{org}/${segment}`].post.responses["412"];
    delete paths[`/orgs/{org}/${segment}`].post.responses["428"];
    paths[`/orgs/{org}/${segment}/{id}`] = { get: read("Resource", [org, id]), put: write("put", [org, id, match]), delete: write("delete", [org, id, match]) };
    delete paths[`/orgs/{org}/${segment}/{id}`].delete.responses["413"];
    delete paths[`/orgs/{org}/${segment}/{id}`].delete.responses["415"];
  }
  return { schemas, responses, paths };
}

export function generateInventoryTypes(document) {
  const definitions = inventoryDefinitions();
  for (const [section, values] of Object.entries(definitions)) {
    const actual = section === "paths" ? document.paths : document.components?.[section];
    for (const [name, expected] of Object.entries(values)) {
      if (!isDeepStrictEqual(actual?.[name], expected)) throw new Error(`D-137 inventory ${section}.${name} differs from its exact contract`);
    }
  }
  const fieldTypes = {
    Host: "{ name: string; address: string; port?: number; tags?: Record<string, string>; groups?: Record<string, true>; favorite?: boolean; notes?: string; default_profile?: string; ssh_options?: Record<string, string>; mosh?: Record<string, string>; }",
    AccessProfile: "{ host: string; name?: string; username: string; route?: string | 0; terminal_profile?: string; startup_command?: string; agent_forwarding?: boolean; }",
    Route: "{ name: string; kind: 1; hops: string[] } | { name: string; kind: 2 | 3; proxy: string } | { name: string; kind: 4; command: string } | { name: string; kind: 5; gateway_network: string }",
    HostGroup: "{ name: string; parent?: string; color?: string; defaults?: Record<string, string>; }",
    TrustRecord: "{ host?: string; pattern?: string; key?: string; fingerprint?: string; provenance?: 1 | 2 | 3 | 4; revoked?: boolean; ca?: boolean; } & ({ host: string } | { pattern: string })",
    Snippet: "{ name: string; template: string; variables?: Record<string, InventorySnippetVariable>; tags?: Record<string, true>; folder?: string; }",
    GatewayNetwork: "{ name?: string; description?: string; }",
  };
  const lines = [
    'export type InventorySnippetVariable = { kind: 1; default?: string } | { kind: 2; default?: string } | { kind: 3; choices: string[]; default?: string } | { kind: 4 };',
    'export type InventoryBodyTooLargeProblem = ProblemDetails & { status: 413; code: "organization.invalid_request"; changed: false; retryable: false };', "",
  ];
  for (const [name] of kinds) {
    const prefix = `Inventory${name}`;
    lines.push(`export type ${prefix}Fields = ${fieldTypes[name]};`,
      `export type ${prefix}ReadFields = ${prefix}Fields${name === "TrustRecord" ? " & { accepted_at: string; accepted_by_device: string; accepted_by_account: string }" : ""};`,
      `export interface ${prefix}CreateRequest { id: string; data: { fields: ${prefix}Fields }; }`,
      `export interface ${prefix}ReplaceRequest { data: { fields: ${prefix}Fields }; }`,
      `export interface ${prefix}Resource { id: string; etag: string; created_at: string; updated_at: string; data: { schema: 1; fields: ${prefix}ReadFields; [extension: string]: unknown }; [extension: string]: unknown; }`,
      `export interface ${prefix}Page { items: ${prefix}Resource[]; next_cursor: string | null; [extension: string]: unknown; }`, "");
  }
  return lines.join("\n");
}
