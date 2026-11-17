// SPDX-License-Identifier: Apache-2.0
import type { InventoryImportFields, InventoryImportRow, InventoryImportRequest, InventoryImportResult, components } from "./index";
const fields: InventoryImportFields = { name: "Example", address: "example.test", port: 22, username: "operator" };
const row: InventoryImportRow = { host_id: "new-host-id", access_profile_id: "new-login-id", ...fields };
const request: InventoryImportRequest = { rows: [row] };
const result: InventoryImportResult = { items: [{ host_id: row.host_id, access_profile_id: row.access_profile_id, extension: true }], extension: null };
const schema: components["schemas"]["InventoryImportRequest"] = request;
void [result, schema];
// @ts-expect-error A required remote username cannot be omitted.
const missing: InventoryImportFields = { name: "Example", address: "example.test", port: 22 };
// @ts-expect-error Optional login_name is omitted, never null.
const nullable: InventoryImportFields = { ...fields, login_name: null };
// @ts-expect-error The request has flat typed fields, without arbitrary K-1 data.
const unknown: InventoryImportRow = { ...row, credential: "unavailable" };
void [missing, nullable, unknown];
