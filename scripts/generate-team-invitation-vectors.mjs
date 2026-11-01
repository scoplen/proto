// SPDX-License-Identifier: Apache-2.0
// Independent D-136 known answers using Node's SHA-256 and explicit wire byte construction.
import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";

const root = new URL("../", import.meta.url);
const base = {
  origin: "https://control.example.com",
  organization_id: "019c8a50-1000-7000-8000-000000000001",
  invitation_id: "019c8a50-1000-7000-8000-000000000002",
  password_hex: Buffer.from("0123WXYZ", "ascii").toString("hex"),
};
const variants = [
  ["base", {}],
  ["other-origin", { origin: "https://other.example.com" }],
  ["origin-port", { origin: "https://control.example.com:8443" }],
  ["origin-ipv4", { origin: "https://127.0.0.1:8443" }],
  ["origin-ipv6", { origin: "https://[2001:db8::1]:8443" }],
  ["maximum-dns-origin", { origin: `https://${[63, 63, 63, 61].map(length => "a".repeat(length)).join(".")}` }],
  ["other-organization", { organization_id: "019c8a50-1000-7000-8000-000000000003" }],
  ["other-invitation", { invitation_id: "019c8a50-1000-7000-8000-000000000004" }],
  ["other-password", { password_hex: Buffer.from("0123WXY0", "ascii").toString("hex") }],
  ["swapped-identifiers", { organization_id: base.invitation_id, invitation_id: base.organization_id }],
  ["maximum-identifiers", { organization_id: "ffffffff-ffff-7fff-bfff-ffffffffffff", invitation_id: "ffffffff-ffff-7fff-bfff-fffffffffffe" }],
];
const vectors = variants.map(([name, changes]) => {
  const input = { ...base, ...changes };
  const origin = Buffer.from(input.origin, "ascii");
  const length = Buffer.alloc(2);
  length.writeUInt16BE(origin.length);
  const bytes = Buffer.concat([
    Buffer.from("spl-team-invitation-v1", "ascii"), length, origin,
    Buffer.from(input.organization_id.replaceAll("-", ""), "hex"),
    Buffer.from(input.invitation_id.replaceAll("-", ""), "hex"),
    Buffer.from(input.password_hex, "hex"),
  ]);
  return { id: `team-invitation-${name}`, kind: "crypto.team-invitation.verifier", input: JSON.stringify(input), expected: createHash("sha256").update(bytes).digest("hex") };
});
for (const [name, changes] of [
  ["http-origin", { origin: "http://control.example.com" }],
  ["uppercase-origin", { origin: "https://CONTROL.example.com" }],
  ["trailing-slash", { origin: `${base.origin}/` }],
  ["default-port", { origin: `${base.origin}:443` }],
  ["nil-organization", { organization_id: "00000000-0000-0000-0000-000000000000" }],
  ["v4-invitation", { invitation_id: "019c8a50-1000-4000-8000-000000000002" }],
  ["wrong-variant", { invitation_id: "019c8a50-1000-7000-7000-000000000002" }],
]) vectors.push({ id: `team-invitation-${name}`, kind: "crypto.team-invitation.verifier", input: JSON.stringify({ ...base, ...changes }), expected: "reject" });
for (const [name, text, expected] of [
  ["digits", "01234567", "accept"], ["letters", "ABCDEFGH", "accept"],
  ["middle", "JKMNPQRS", "accept"], ["last", "TVWXYZ01", "accept"],
  ["short", "0123456", "reject"], ["long", "012345678", "reject"],
  ["lowercase", "abcdefg0", "reject"], ["alias-i", "I1234567", "reject"],
  ["alias-l", "L1234567", "reject"], ["alias-o", "O1234567", "reject"],
  ["alias-u", "U1234567", "reject"], ["space", " 1234567", "reject"],
  ["separator", "012-4567", "reject"], ["newline", "0123456\n", "reject"],
  ["nul", "0123456\0", "reject"], ["unicode", "012345é", "reject"],
]) vectors.push({ id: `team-invitation-password-${name}`, kind: "crypto.team-invitation.password", input: Buffer.from(text, "utf8").toString("hex"), expected });

const outputs = [["vectors/team-invitation.json", Buffer.from(`${JSON.stringify({ format: "scoplen-test-vectors", version: 1, vectors }, null, 2)}\n`)]];
for (const vector of vectors) {
  const bytes = vector.kind === "crypto.team-invitation.password" ? Buffer.from(vector.input, "hex") : (() => {
    const input = JSON.parse(vector.input);
    return Buffer.concat([Buffer.from(input.password_hex, "hex"), Buffer.from(`${input.origin}\n${input.organization_id}\n${input.invitation_id}`, "utf8")]);
  })();
  outputs.push([`fuzz/corpus/crypto_decoders/seed-${vector.id}`, bytes]);
}
for (const [path, expected] of outputs) {
  const output = new URL(path, root);
  if (process.argv.includes("--check")) {
    const actual = await readFile(output);
    const normalized = path.endsWith(".json") ? Buffer.from(actual.toString("utf8").replaceAll("\r\n", "\n")) : actual;
    if (!normalized.equals(expected)) throw new Error(`D-136 invitation output is stale: ${path}`);
  } else await writeFile(output, expected);
}
console.log(`validated ${vectors.length} independent D-136 invitation vectors`);
