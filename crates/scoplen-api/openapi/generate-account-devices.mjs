// SPDX-License-Identifier: Apache-2.0
// D-113 complete signed-statement contract checks and TypeScript projection.
export function generateAccountDeviceTypes(document) {
  const operation = document.paths?.["/accounts/me/devices"]?.get;
  const schema = document.components?.schemas?.AccountDeviceStatements;
  const fields = ["account_id", "certificates", "revocations"];
  const uuid = "^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$";
  if (operation?.operationId !== "listCurrentAccountDevices" || operation.requestBody ||
      operation.parameters || operation["x-scoplen-required-device-scope"] !== "account:read" ||
      operation["x-scoplen-response-max-bytes"] !== 6291456 ||
      operation["x-scoplen-decoded-artifact-max-bytes"] !== 4194304 ||
      !operation.description?.includes("Idempotency-Key") ||
      !operation.description.includes("If-Match") ||
      !operation.description.includes("every query") ||
      !operation.description.includes("not prove completeness or freshness") ||
      operation.responses?.["200"]?.content?.["application/json"]?.schema?.$ref !== "#/components/schemas/AccountDeviceStatements" ||
      operation.responses["200"].headers?.ETag ||
      schema?.type !== "object" || schema.additionalProperties !== true ||
      JSON.stringify(schema.required) !== JSON.stringify(fields) ||
      JSON.stringify(Object.keys(schema.properties ?? {})) !== JSON.stringify(fields) ||
      schema.properties.account_id?.type !== "string" ||
      schema.properties.account_id.format !== "uuid" ||
      schema.properties.account_id.pattern !== uuid) {
    throw new Error("account device snapshot differs from D-113");
  }
  for (const field of ["certificates", "revocations"]) {
    const array = schema.properties[field];
    if (array?.type !== "array" || array.minItems !== 0 || array.maxItems !== undefined ||
        array["x-scoplen-sort"] !== "strictly-increasing-decoded-bytes" ||
        array.items?.type !== "string" || array.items.minLength !== 2 ||
        array.items.maxLength !== 87382 || array.items.pattern !== "^[A-Za-z0-9_-]+$" ||
        array.items["x-scoplen-decoded-bytes"]?.minimum !== 1 ||
        array.items["x-scoplen-decoded-bytes"]?.maximum !== 65536 ||
        !array.items.description?.includes("nonzero unused pad bits")) {
      throw new Error(`account device ${field} differs from D-113`);
    }
  }
  for (const status of ["200", "400", "401", "403", "503", "default"]) {
    const response = operation.responses?.[status];
    if (response?.headers?.["Cache-Control"]?.required !== true ||
        response.headers["Cache-Control"].schema?.const !== "no-store" ||
        response.headers.Pragma?.required !== true ||
        response.headers.Pragma.schema?.const !== "no-cache") {
      throw new Error(`account device ${status} cache headers differ from D-113`);
    }
  }
  for (const [status, code, retryable] of [
    ["400", "auth.invalid_request", false],
    ["403", "policy.denied", false],
    ["503", "auth.storage_unavailable", true],
  ]) {
    const problem = operation.responses[status].content?.["application/problem+json"]?.schema;
    if (JSON.stringify(problem?.allOf) !== JSON.stringify([
      { $ref: "#/components/schemas/ProblemDetails" },
      { type: "object", properties: {
        status: { const: Number(status) }, code: { const: code },
        changed: { const: false }, retryable: { const: retryable },
      } },
    ])) throw new Error(`account device ${status} failure differs from D-113`);
  }
  return [
    "/** Complete JSON <=6291456 bytes; decoded statements total <=4194304 bytes. */",
    "export interface AccountDeviceStatements {",
    "  account_id: string;",
    "  /** Canonical unpadded base64url, 1..65536 decoded bytes each, strictly ordered by decoded bytes. */",
    "  certificates: string[];",
    "  /** Same bounds/order as certificates; consumers verify every account signature before use. */",
    "  revocations: string[];",
    "  [extension: string]: unknown;",
    "}",
    "",
  ].join("\n");
}
