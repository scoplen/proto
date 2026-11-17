// SPDX-License-Identifier: Apache-2.0
// Independently authored CSV/wire answers; no Rust or production parser is invoked.
import { readFile, readdir, unlink, writeFile } from "node:fs/promises";

const root = new URL("../", import.meta.url);
const vectors = [];
const id = number => `019bdad6-b800-7000-8000-${String(number).padStart(12, "0")}`;
const fields = { name: "Example", address: "example.test", port: 22, username: "operator", login_name: "Operations" };
const row = number => ({ host_id: id(number), access_profile_id: id(number + 1), ...fields });
const request = { rows: [row(10), row(20)] };
const result = { items: request.rows.map(({ host_id, access_profile_id }) => ({ host_id, access_profile_id })) };
const json = JSON.stringify;
const add = (name, kind, input, expected = "rejected") => vectors.push({ id: `inventory-import-${name}-v1`, kind: `inventory.import.${kind}`, input: typeof input === "string" ? input : json(input), expected: typeof expected === "string" ? expected : json(expected) });
const header = "name,address,port,username,login_name";
const csv = (name, source, expected) => add(`csv-${name}`, "csv", Buffer.from(source).toString("hex"), expected);
for (const [name, source, expected] of [
  ["lf", `${header}\nExample,example.test,22,operator,Operations\n`, { rows: [fields] }],
  ["crlf-bom", `\ufeff${header}\r\nExample,example.test,,operator,\r\n`, { rows: [{ ...fields, login_name: undefined }] }],
  ["quoted", `${header}\n"A, ""B""",host.test,65535,user,"line\nname"`, { rows: [{ name: 'A, "B"', address: "host.test", port: 65535, username: "user", login_name: "line\nname" }] }],
  ["whitespace", `${header}\n name , address ,, user , login `, { rows: [{ name: " name ", address: " address ", port: 22, username: " user ", login_name: " login " }] }],
]) csv(name, source, expected);
for (const [name, source, kind, record, field] of [
  ["empty", "", "empty_input"], ["header-only", header, "empty_input"], ["double-bom", `\ufeff\ufeff${header}\nx,h,,u,`, "invalid_header"],
  ["duplicate-header", "name,address,port,username,username\nx,h,,u,", "invalid_header"],
  ["header-order", "address,name,port,username,login_name\nx,h,,u,", "invalid_header"],
  ["header-extra", `${header},extra\nx,h,,u,`, "invalid_header"],
  ["quote-unclosed", `${header}\n"x,h,,u,`, "invalid_csv", 1],
  ["quote-unquoted", `${header}\nx"q,h,,u,`, "invalid_csv", 1],
  ["quote-tail", `${header}\n"x" q,h,,u,`, "invalid_csv", 1],
  ["bare-cr", `${header}\nx,h,,u,\r`, "invalid_csv", 1],
  ["blank", `${header}\n\n`, "invalid_csv", 1],
  ["extra-cell", `${header}\nx,h,,u,,extra`, "invalid_csv", 1],
  ["missing-cell", `${header}\nx,h,,u`, "invalid_csv", 1],
  ["name-empty", `${header}\n,h,,u,`, "invalid_cell", 1, "name"],
  ["address-empty", `${header}\nx,,,u,`, "invalid_cell", 1, "address"],
  ["user-empty", `${header}\nx,h,,,`, "invalid_cell", 1, "username"],
  ["non-nfc", `${header}\ne\u0301,h,,u,`, "invalid_cell", 1, "name"],
  ["data-record", `${header}\n"x\ny\nz",h,,u,\n,h,,u,`, "invalid_cell", 2, "name"],
]) csv(name, source, { kind, ...(record ? { record } : {}), ...(field ? { field } : {}) });
for (const port of ["0", "01", "+22", "-1", "65536", "22.0", "22e0", " 22", "22 "]) csv(`port-${Buffer.from(port).toString("hex")}`, `${header}\nx,h,${port},u,`, { kind: "invalid_cell", record: 1, field: "port" });
add("utf8", "csv", "ff", { kind: "invalid_utf8" });
for (const count of [1, 100, 101]) {
  const source = `${header}\n${"x,h,,u,\n".repeat(count)}`;
  csv(`rows-${count}`, source, count <= 100 ? { rows: Array.from({ length: count }, () => ({ name: "x", address: "h", port: 22, username: "u" })) } : { kind: "too_many_records", record: 101 });
}
for (const count of [16384, 16385]) csv(`text-${count}`, `${header}\n${"x".repeat(count)},h,,u,`, count === 16384 ? { rows: [{ name: "x".repeat(count), address: "h", port: 22, username: "u" }] } : { kind: "invalid_cell", record: 1, field: "name" });
add("request", "request", request, request);
add("result", "result", result, result);
add("result-extensions", "result", { ...result, extension: null, items: result.items.map(item => ({ ...item, extra: true })) }, result);
for (const token of ["22.0", "22e0", '"22"', "0", "65536", "null", "true"]) add(`json-port-${Buffer.from(token).toString("hex")}`, "request", json(request).replace('"port":22', `"port":${token}`));
for (const field of ["name", "address", "username", "login_name"]) for (const [name, value] of [["empty", ""], ["null", null], ["non-nfc", "e\u0301"]]) {
  const valueRequest = structuredClone(request); valueRequest.rows[0][field] = value; add(`${field}-${name}`, "request", valueRequest);
}
for (const [name, edit] of [
  ["id-repeated", body => body.rows[1].host_id = body.rows[0].access_profile_id],
  ["id-case", body => body.rows[0].host_id = body.rows[0].host_id.toUpperCase()],
  ["id-version", body => body.rows[0].host_id = body.rows[0].host_id.replace("-7000-", "-4000-")],
  ["unknown", body => body.rows[0].credential = id(99)], ["rows-empty", body => body.rows = []],
]) { const body = structuredClone(request); edit(body); add(name, "request", body); }
add("duplicate", "request", json(request).replace('"name":', '"name":"duplicate","name":'));
add("recursive-duplicate", "request", json(request).replace(/}$/, ',"extension":{"x":1,"x":2}}'));
add("null-rows", "request", { rows: null });
for (const [name, changed] of [["reverse", { items: result.items.toReversed() }], ["missing", { items: result.items.slice(0, 1) }], ["different", { items: [{ host_id: id(99), access_profile_id: id(98) }, result.items[1]] }]]) add(`binding-${name}`, "binding", { request, result: changed });
add("binding-exact", "binding", { request, result }, "accepted");
for (const [kind, bound] of [["csv", 1048576], ["request", 2097152], ["result", 32768]]) for (const extra of [0, 1]) add(`${kind}-bound-${extra}`, "bound", { kind, bytes: bound + extra, base: kind === "request" ? json(request) : kind === "result" ? json(result) : "" }, extra ? "rejected" : "accepted");
const outputs = [["vectors/organization-inventory-import.json", Buffer.from(json({ format: "scoplen-test-vectors", version: 1, vectors }, null, 2) + "\n")]];
for (const vector of vectors.filter(vector => ["csv", "request", "result"].some(kind => vector.kind === `inventory.import.${kind}`))) outputs.push([`fuzz/corpus/api_json/seed-${vector.id}`, vector.kind.endsWith(".csv") ? Buffer.from(vector.input, "hex") : Buffer.from(vector.input)]);
const expectedSeeds = new Set(outputs.slice(1).map(([path]) => path.split("/").at(-1)));
for (const entry of await readdir(new URL("fuzz/corpus/api_json/", root), { withFileTypes: true })) {
  if (!entry.isFile() || !entry.name.startsWith("seed-inventory-import-") || expectedSeeds.has(entry.name)) continue;
  if (process.argv.includes("--check")) throw new Error(`D-151 stale seed: ${entry.name}`);
  await unlink(new URL(`fuzz/corpus/api_json/${entry.name}`, root));
}
for (const [path, expected] of outputs) {
  const url = new URL(path, root);
  if (process.argv.includes("--check")) { const actual = await readFile(url); if (!actual.equals(expected)) throw new Error(`D-151 stale output: ${path}`); }
  else await writeFile(url, expected);
}
console.log(`validated ${vectors.length} independent D-151 vectors and ${outputs.length - 1} seeds`);
