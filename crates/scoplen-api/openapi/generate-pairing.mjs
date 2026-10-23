// SPDX-License-Identifier: Apache-2.0
// Validate the finite D-114 transport and project its authored schemas to TypeScript.
export function generatePairingTypes(document) {
  const schemas = document.components?.schemas;
  const routes = [
    ["/auth/pairings", "post", "createPairing", 256, 4096],
    ["/auth/pairings/{pairing}", "get", "getPairing", 0, 8388608],
    ["/auth/pairings/{pairing}", "delete", "cancelPairing", 0, 0],
    ["/auth/pairings/{pairing}/claim", "post", "claimPairing", 256, 4096],
    ["/auth/pairings/{pairing}/messages", "post", "postPairingMessage", 6291456, 256],
    ["/auth/pairings/{pairing}/complete", "post", "completePairing", 6291456, 256],
  ];
  for (const [path, method, id, requestMax, responseMax] of routes) {
    const op = document.paths?.[path]?.[method];
    const old = { accessToken: [], dpopProof: [] };
    const expectedSecurity = id === "createPairing" ? [] :
      ["claimPairing", "completePairing"].includes(id) ? [old] : [old, { pairingCapability: [] }];
    if (op?.operationId !== id || op["x-scoplen-request-max-bytes"] !== requestMax ||
        op["x-scoplen-response-max-bytes"] !== responseMax ||
        JSON.stringify(op.security) !== JSON.stringify(expectedSecurity) ||
        (id !== "createPairing" && op["x-scoplen-required-device-scope"] !== "keys:write") ||
        !op.description?.includes("Idempotency-Key") || !op.description.includes("unknown request fields")) {
      throw new Error(`pairing operation ${id} differs from D-114`);
    }
    for (const entry of Object.values(op.responses ?? {})) {
      const response = entry.$ref ? document.components.responses[entry.$ref.split("/").at(-1)] : entry;
      for (const [name, value] of [["Cache-Control", "no-store"], ["Pragma", "no-cache"], ["Referrer-Policy", "no-referrer"]]) {
        if (response.headers?.[name]?.required !== true || response.headers[name].schema?.const !== value) {
          throw new Error(`pairing ${id} response lacks ${name}`);
        }
      }
    }
    const rate = document.components.responses[op.responses["429"].$ref.split("/").at(-1)];
    if (rate.headers["RateLimit-Policy"].schema.const !==
          (id === "getPairing" ? '"pairing";q=120;w=60' : '"pairing";q=30;w=60') ||
        rate.headers["Retry-After"].schema.pattern !== "^(?:[1-9]|[1-9][0-9]|[12][0-9]{2}|300)$" ||
        rate.headers.RateLimit.schema.pattern !== '^"pairing";r=0;t=(?:[1-9]|[1-9][0-9]|[12][0-9]{2}|300)$') {
      throw new Error(`pairing ${id} rate headers differ from D-114`);
    }
  }
  const steps = ["initiator_share", "responder_share", "responder_confirmation", "initiator_confirmation", "new_device", "handoff", "acceptance"];
  for (const [name, request] of [["PairingMessageRequest", true], ["PairingRelayMessage", false]]) {
    const alternatives = schemas?.[name]?.oneOf;
    if (alternatives?.length !== 7) throw new Error("pairing must have exactly seven slot alternatives");
    for (let index = 0; index < steps.length; index++) {
      const slot = alternatives[index];
      const bounds = index === 4 ? [41, 131072] : index === 5 ? [41, 4456448] :
        index === 6 ? [64, 64] : [32, 32];
      const payload = slot.properties?.payload;
      if (slot.additionalProperties !== !request ||
          JSON.stringify(slot.required) !== JSON.stringify(["step", "payload"]) ||
          slot.properties?.step?.const !== steps[index] ||
          payload?.["x-scoplen-decoded-bytes"]?.minimum !== bounds[0] ||
          payload?.["x-scoplen-decoded-bytes"]?.maximum !== bounds[1] ||
          payload.pattern !== "^[A-Za-z0-9_-]+$") {
        throw new Error(`${name} slot ${index} differs from D-114`);
      }
    }
  }
  if (JSON.stringify(schemas?.PairingStep?.enum) !== JSON.stringify(steps) ||
      schemas.PairingSnapshot?.properties?.messages?.maxItems !== 7 ||
      schemas.PairingCompleteRequest?.properties?.device_certificate?.["x-scoplen-decoded-bytes"]?.maximum !== 65536 ||
      schemas.PairingCompleteRequest?.properties?.key_bundle_update?.["x-scoplen-decoded-bytes"]?.maximum !== 4194304 ||
      schemas.PairingCompleteRequest?.properties?.new_device_signature?.["x-scoplen-decoded-bytes"]?.maximum !== 64) {
    throw new Error("pairing artifact or transcript limits differ from D-114");
  }
  const render = schema => {
    if (schema.$ref) return schema.$ref.split("/").at(-1);
    if (schema.oneOf) return schema.oneOf.map(render).join(" | ");
    if (schema.const !== undefined) return JSON.stringify(schema.const);
    if (schema.enum) return schema.enum.map(value => JSON.stringify(value)).join(" | ");
    if (schema.type === "null") return "null";
    if (schema.type === "array") return `(${render(schema.items)})[]`;
    if (schema.type === "integer") return "number";
    if (schema.type === "string") return "string";
    if (schema.type === "object") {
      const fields = Object.entries(schema.properties ?? {}).map(([name, value]) => `${name}: ${render(value)};`);
      if (schema.additionalProperties) fields.push("[extension: string]: unknown;");
      return fields.length ? `{ ${fields.join(" ")} }` : "Record<string, never>";
    }
    throw new Error("unsupported pairing schema");
  };
  return Object.entries(schemas).filter(([name]) => name.startsWith("Pairing"))
    .map(([name, schema]) => `export type ${name} = ${render(schema)};\n`).join("\n");
}
