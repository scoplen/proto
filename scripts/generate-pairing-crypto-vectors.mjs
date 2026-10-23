// SPDX-License-Identifier: Apache-2.0
// Independent Node CBOR/hash/signature producer; all keys are synthetic fixture material.
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  createECDH,
  sign,
  verify,
} from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { resolve, dirname } from "node:path";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const read = (name) =>
  JSON.parse(readFileSync(resolve(root, "vectors", name), "utf8")).vectors;
const crypto = read("crypto.json"),
  hierarchy = read("account-hierarchy.json");
const hex = (s) => Buffer.from(s, "hex");
const uuid = (s) => hex(s.replaceAll("-", ""));
const hash = (...values) => {
  const h = createHash("sha256");
  for (const v of values) h.update(v);
  return h.digest();
};
function head(major, n) {
  if (n < 24) return Buffer.from([(major << 5) | n]);
  const size = n <= 255 ? 1 : n <= 65535 ? 2 : 4;
  const out = Buffer.alloc(size + 1);
  out[0] = (major << 5) | { 1: 24, 2: 25, 4: 26 }[size];
  out.writeUIntBE(n, 1, size);
  return out;
}
function cbor(v) {
  if (Buffer.isBuffer(v)) return Buffer.concat([head(2, v.length), v]);
  if (typeof v === "string") {
    const b = Buffer.from(v);
    return Buffer.concat([head(3, b.length), b]);
  }
  if (typeof v === "number") return head(0, v);
  if (Array.isArray(v))
    return Buffer.concat([head(4, v.length), ...v.map(cbor)]);
  const pairs = Object.entries(v)
    .map(([k, x]) => [cbor(k), cbor(x)])
    .sort((a, b) => Buffer.compare(a[0], b[0]));
  return Buffer.concat([head(5, pairs.length), ...pairs.flat()]);
}
const context = {
  origin: "https://control.example.com",
  pairing_id: "03000000-0000-7000-8000-000000000004",
  initiator_device_id: "03000000-0000-7000-8000-000000000001",
  responder_device_id: "03000000-0000-7000-8000-000000000000",
};
const wireContext = {
  ...context,
  pairing_id: uuid(context.pairing_id),
  initiator_device_id: uuid(context.initiator_device_id),
  responder_device_id: uuid(context.responder_device_id),
};
const cert = crypto.find((v) => v.kind === "crypto.device-certificate");
const certificate = hex(cert.expected);
const qr = crypto.find((v) => v.kind === "crypto.qr-pairing").input.split("|");
const device = {
  ...wireContext,
  signing_public_key: hex(qr[2]),
  kem_public_key: hex(qr[1]),
  display_name: "Test device",
  platform: "test",
  created_at: 42,
};
const artifact = (kind, index) =>
  hex(hierarchy.find((v) => v.kind === kind).input.split("|")[index]);
const projection = {
  revision: 2,
  wrapped_ark: artifact("crypto.hierarchy.device-ark-open", 3),
  account_signing_key: artifact("crypto.hierarchy.account-signing-open", 3),
  account_kem_key: artifact("crypto.hierarchy.account-kem-open", 3),
  recovery_blob: hex(
    crypto.find((v) => v.kind === "crypto.recovery-blob").expected,
  ),
};
const anchor = hash("spl-pairing-key-anchor-v1", cbor(projection));
const edPrivate = createPrivateKey({
  key: Buffer.concat([
    Buffer.from([
      0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
      0x04, 0x22, 0x04, 0x20,
    ]),
    Buffer.alloc(32, 1),
  ]),
  format: "der",
  type: "pkcs8",
});
const edPublic = createPublicKey(edPrivate)
  .export({ format: "der", type: "spki" })
  .subarray(-32);
const handoff = {
  ...wireContext,
  account_id: uuid("04000000-0000-7000-8000-000000000000"),
  personal_vault_id: uuid("05000000-0000-7000-8000-000000000000"),
  account_signing_public_key: edPublic,
  account_kem_public_key: Buffer.alloc(32, 8),
  device_certificate: certificate,
  ...projection,
  key_bundle_update_hash: hash(Buffer.from([0xa0])),
  key_anchor: anchor,
  personal_vault_keys: cbor({
    keys: [
      {
        epoch: 1,
        wrapped_vault_key: artifact("crypto.hierarchy.personal-vault-open", 4),
      },
    ],
  }),
};
const vectors = [];
const add = (id, kind, input, expected) =>
  vectors.push({ id, kind, input, expected });
const deviceBytes = cbor(device),
  handoffBytes = cbor(handoff);
add(
  "pairing-new-device",
  "crypto.pairing-new-device",
  deviceBytes.toString("hex"),
  deviceBytes.toString("hex"),
);
add(
  "pairing-handoff",
  "crypto.pairing-handoff",
  handoffBytes.toString("hex"),
  handoffBytes.toString("hex"),
);
for (const [name, v] of [
  ["unknown", { ...device, extra: 1 }],
  ["bad-key", { ...device, signing_public_key: Buffer.alloc(65, 4) }],
])
  add(
    `pairing-new-${name}`,
    "crypto.pairing-new-device",
    cbor(v).toString("hex"),
    "reject",
  );
for (const [name, v] of [
  ["root", { ...handoff, account_signing_public_key: Buffer.alloc(32, 1) }],
  ["anchor", { ...handoff, key_anchor: Buffer.alloc(32) }],
  ["revision", { ...handoff, revision: 0 }],
  [
    "device",
    { ...handoff, responder_device_id: uuid(context.initiator_device_id) },
  ],
])
  add(
    `pairing-handoff-${name}`,
    "crypto.pairing-handoff",
    cbor(v).toString("hex"),
    "reject",
  );
for (const [kind, bytes] of [
  ["new-device", deviceBytes],
  ["handoff", handoffBytes],
])
  add(
    `pairing-${kind}-trailing`,
    `crypto.pairing-${kind}`,
    Buffer.concat([bytes, Buffer.from([0])]).toString("hex"),
    "reject",
  );
const jsonProjection = Object.fromEntries(
  Object.entries(projection).map(([k, v]) => [
    k,
    Buffer.isBuffer(v) ? v.toString("hex") : v,
  ]),
);
add(
  "pairing-key-anchor",
  "crypto.pairing-key-anchor",
  JSON.stringify(jsonProjection),
  anchor.toString("hex"),
);
// Opaque synthetic frame/update bytes test this signature-input boundary, not K-4 validity.
const frame = Buffer.concat([Buffer.alloc(40, 9), handoffBytes]),
  update = Buffer.from([0xa0]);
const length = Buffer.alloc(2);
length.writeUInt16BE(Buffer.byteLength(context.origin));
const input = Buffer.concat([
  Buffer.from("spl-pairing-complete-v1"),
  length,
  Buffer.from(context.origin),
  uuid(context.pairing_id),
  uuid(context.initiator_device_id),
  uuid(context.responder_device_id),
  handoff.account_id,
  hash(frame),
  hash(certificate),
  hash(update),
]);
const ec = createECDH("prime256v1");
ec.setPrivateKey(Buffer.alloc(32, 2));
const pub = ec.getPublicKey();
const privateKey = createPrivateKey({
  key: {
    kty: "EC",
    crv: "P-256",
    x: pub.subarray(1, 33).toString("base64url"),
    y: pub.subarray(33).toString("base64url"),
    d: Buffer.alloc(32, 2).toString("base64url"),
  },
  format: "jwk",
});
// Reuse a valid previous independent signature so regeneration is stable despite ECDSA randomness.
let signature;
try {
  const old = read("pairing-crypto.json").find(
    (v) => v.kind === "crypto.pairing-acceptance",
  );
  if (old && old.expected.split("|")[0] === input.toString("hex")) {
    const candidate = hex(old.expected.split("|")[1]);
    if (
      verify(
        "sha256",
        input,
        { key: createPublicKey(privateKey), dsaEncoding: "ieee-p1363" },
        candidate,
      )
    )
      signature = candidate;
  }
} catch {
  /* Initial generation. */
}
signature ??= sign("sha256", input, {
  key: privateKey,
  dsaEncoding: "ieee-p1363",
});
add(
  "pairing-acceptance",
  "crypto.pairing-acceptance",
  JSON.stringify({
    ...context,
    account_id: "04000000-0000-7000-8000-000000000000",
    frame: frame.toString("hex"),
    certificate: certificate.toString("hex"),
    update: update.toString("hex"),
    public_key: pub.toString("hex"),
  }),
  input.toString("hex") + "|" + signature.toString("hex"),
);
add(
  "pairing-approval",
  "crypto.pairing-approval",
  [certificate, update, signature].map((b) => b.toString("hex")).join("|"),
  hash(
    "spl-pairing-approval-v1",
    cbor({
      device_certificate: certificate,
      key_bundle_update: update,
      new_device_signature: signature,
    }),
  ).toString("hex"),
);
const link = `${context.origin}/pair#id=${context.pairing_id}`;
add("pairing-link", "crypto.pairing-link", link, link);
for (const [name, bad] of [
  ["query", link.replace("/pair#", "/pair?password=01234567#")],
  ["extra", link + "&password=01234567"],
  ["http", link.replace("https:", "http:")],
])
  add(`pairing-link-${name}`, "crypto.pairing-link", bad, "reject");
const oldQr = crypto.find((v) => v.kind === "crypto.qr-pairing").expected;
add("pairing-qr-v2", "crypto.pairing-qr", oldQr, oldQr);
add(
  "pairing-qr-v1",
  "crypto.pairing-qr",
  oldQr.replace("splpair2:", "splpair1:"),
  "reject",
);
writeFileSync(
  resolve(root, "vectors/pairing-crypto.json"),
  JSON.stringify(
    { format: "scoplen-test-vectors", version: 1, vectors },
    null,
    2,
  ) + "\n",
);
const corpus = resolve(root, "fuzz/corpus/crypto_decoders");
mkdirSync(corpus, { recursive: true });
for (const [name, bytes] of [
  ["pairing-new-device", deviceBytes],
  ["pairing-handoff", handoffBytes],
  ["pairing-link", Buffer.from(link)],
  ["pairing-qr-v2", Buffer.from(oldQr)],
  ["pairing-qr-v1", Buffer.from(oldQr.replace("splpair2:", "splpair1:"))],
])
  writeFileSync(resolve(corpus, "seed-" + name), bytes);
