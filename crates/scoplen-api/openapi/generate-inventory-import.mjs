// SPDX-License-Identifier: Apache-2.0
import { isDeepStrictEqual } from "node:util";

const ref = name => ({ $ref: `#/components/schemas/${name}` });
const uuid = { type: "string", format: "uuid", pattern: "^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$" };
const text = { type: "string", minLength: 1, maxLength: 16384, "x-scoplen-max-utf8-bytes": 16384, description: "Nonempty NFC K-1 text, preserved without trimming or normalization; complete-object limits also apply." };
const object = (properties, required = Object.keys(properties), additionalProperties = false) => ({ type: "object", additionalProperties, required, properties });
const headers = { "Cache-Control": { required: true, schema: { type: "string", const: "no-store" } }, Pragma: { required: true, schema: { type: "string", const: "no-cache" } }, "X-Request-ID": { required: true, schema: { type: "string", minLength: 1 } } };

export function inventoryImportDefinitions() {
  const fields = { name: text, address: text, port: { type: "integer", minimum: 1, maximum: 65535, "x-scoplen-integer-token": true, description: "Exact JSON integer token, without decimal/exponent/string aliases." }, username: text, login_name: text };
  const schemas = {
    InventoryImportFields: object(fields, ["name", "address", "port", "username"]),
    InventoryImportRow: object({ host_id: uuid, access_profile_id: uuid, ...fields }, ["host_id", "access_profile_id", "name", "address", "port", "username"]),
    InventoryImportRequest: { ...object({ rows: { type: "array", minItems: 1, maxItems: 100, items: ref("InventoryImportRow"), description: "Preserve row order. All 2*N identities are distinct newly allocated canonical UUIDv7 values; duplicate names/endpoints are permitted." } }), "x-scoplen-max-bytes": 2097152 },
    InventoryImportPair: object({ host_id: uuid, access_profile_id: uuid }, undefined, true),
    InventoryImportResult: { ...object({ items: { type: "array", minItems: 1, maxItems: 100, items: ref("InventoryImportPair"), description: "Verify exact count, order and every submitted id against the original request before reporting success." } }, undefined, true), "x-scoplen-max-bytes": 32768 },
  };
  const problem = suffix => ({ $ref: `#/components/responses/Organization${suffix}` });
  const post = {
    operationId: "createInventoryImport",
    security: [{ accessToken: [], dpopProof: [] }],
    "x-scoplen-required-device-scope": "inventory:write",
    "x-scoplen-cedar-action": "manage_inventory",
    "x-scoplen-request-max-bytes": 2097152,
    "x-scoplen-response-max-bytes": 32768,
    description: "D-151 synchronous atomic creation of 1..100 Direct Host/default-Login pairs. Require current Account/Device or Account-browser family, active same-Organization Membership and manage_inventory. Reject query and If-Match. Validate the entire prospective reciprocal pair graph and independent view_inventory on every referenced object; reject used/tombstoned ids and include all 2*N objects in the existing quota. Commit canonical K-1/projection/reference/history state with real writer origins, contiguous Host-then-Login sequences, one view revision, one existing attributable organization.inventory_created audit per object and the original receipt atomically; mandatory audit/encoding failure rolls back everything. Emit one changed-only hint after commit. A 24-hour receipt under spl-organization-inventory-import-v1 binds trusted origin/Account/real writer kind and id/POST/full Organization path/canonical ordered typed rows and ids. Check matching receipt before unused ids/quota/new-object checks; current Account/writer/Membership/manage_inventory remain required, without rebuilding the historical graph. Same-family browser refresh retains binding; another writer or payload conflicts. Original explicit confirmation returns only ordered ids without another mutation/audit/hint. Unknown COMMIT is organization.commit_outcome_unknown changed=true retryable=true; retain original intent, never regenerate ids/key or automatically replay. No job Resource, Location or polling.",
    parameters: [{ name: "org", in: "path", required: true, schema: uuid }, { name: "Idempotency-Key", in: "header", required: true, schema: uuid }],
    requestBody: { required: true, description: "Complete UTF-8 JSON <=2097152 bytes including whitespace. Reject recursive duplicate names, unknown fields/null and integer aliases. Only login_name may be omitted. Each final K-1 object <=262144 bytes with actual committing clocks.", content: { "application/json": { schema: ref("InventoryImportRequest") } } },
    responses: {
      "201": { description: "Confirmed original ordered identities, <=32768 complete bytes including response extensions. Read ordinary inventory for current Resources/ETags.", headers, content: { "application/json": { schema: ref("InventoryImportResult") } } },
      "400": problem("InvalidRequest"), "401": problem("AuthenticationRequired"), "403": problem("Denied"), "404": problem("NotFound"), "409": problem("Conflict"), "413": { $ref: "#/components/responses/InventoryBodyTooLarge" }, "415": problem("ContentType"),
      "503": { description: "Confirmed rollback: organization.storage_unavailable changed=false retryable=true. Unconfirmed COMMIT: organization.commit_outcome_unknown changed=true retryable=true; only explicit original confirmation with a fresh proof within its original 24-hour window.", headers, content: { "application/problem+json": { schema: { oneOf: [ref("OrganizationStorageUnavailableProblem"), ref("OrganizationCommitOutcomeUnknownProblem")] } } } },
      default: { description: "Existing bounded Problem <=4096 bytes and authentication/admission headers; no partial success body.", headers, content: { "application/problem+json": { schema: ref("ProblemDetails") } } },
    },
  };
  return { schemas, paths: { "/orgs/{org}/inventory/imports": { post } } };
}

export function generateInventoryImportTypes(document) {
  const expected = inventoryImportDefinitions();
  for (const [name, schema] of Object.entries(expected.schemas)) if (!isDeepStrictEqual(document.components?.schemas?.[name], schema)) throw new Error(`D-151 schema drift: ${name}`);
  for (const [path, operation] of Object.entries(expected.paths)) if (!isDeepStrictEqual(document.paths?.[path], operation)) throw new Error(`D-151 operation drift: ${path}`);
  if (document.paths?.["/orgs/{org}/inventory/imports/{id}"] || document.components?.schemas?.InventoryImport) throw new Error("D-151 retains provisional import-job CRUD");
  return `export interface InventoryImportFields { name: string; address: string; port: number; username: string; login_name?: string; }
export interface InventoryImportRow extends InventoryImportFields { host_id: string; access_profile_id: string; }
export interface InventoryImportRequest { rows: InventoryImportRow[]; }
export interface InventoryImportPair { host_id: string; access_profile_id: string; [extension: string]: unknown; }
export interface InventoryImportResult { items: InventoryImportPair[]; [extension: string]: unknown; }
`;
}
