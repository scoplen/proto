// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { createCipheriv, createHmac, createPrivateKey, createPublicKey, diffieHellman, sign } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";

const hex = value => Buffer.from(value, "hex");
const toHex = bytes => bytes.toString("hex");
const ascii = value => Buffer.from(value, "ascii");
const join = (...parts) => Buffer.concat(parts);
const empty = Buffer.alloc(0);
const hmac = (salt, input) => createHmac("sha256", salt).update(input).digest();
function integer(length, number) {
  const bytes = Buffer.alloc(length);
  if (length === 8) bytes.writeBigUInt64BE(BigInt(number));
  else bytes.writeUIntBE(number, 0, length);
  return bytes;
}
function uuid(last) {
  return `00000000-0000-7000-8000-${last.toString(16).padStart(12, "0")}`;
}
const uuidBytes = value => hex(value.replaceAll("-", ""));
const privateKey = (oid, seed) => createPrivateKey({
  key: join(hex(`302e020100300506032b65${oid}04220420`), seed), format: "der", type: "pkcs8",
});
const publicBytes = key => key.export({ format: "der", type: "spki" }).subarray(-32);

function hpke(context, receiver, plaintext, ephemeral) {
  const recipientPublic = createPublicKey(receiver);
  const enc = publicBytes(createPublicKey(ephemeral));
  const dh = diffieHellman({ privateKey: ephemeral, publicKey: recipientPublic });
  const kem = hex("0020");
  const kemSuite = join(ascii("KEM"), kem);
  const suite = join(ascii("HPKE"), kem, hex("00010003"));
  // RFC 9180 LabeledExtract and LabeledExpand. These test outputs fit in the first HKDF block.
  const label = (suiteId, name, input) => join(ascii("HPKE-v1"), suiteId, ascii(name), input);
  const extract = (salt, suiteId, name, input) => hmac(salt, label(suiteId, name, input));
  const expand = (key, suiteId, name, input, length) =>
    hmac(key, join(integer(2, length), label(suiteId, name, input), Buffer.of(1))).subarray(0, length);
  const eae = extract(empty, kemSuite, "eae_prk", dh);
  const shared = expand(eae, kemSuite, "shared_secret", join(enc, publicBytes(recipientPublic)), 32);
  const schedule = join(Buffer.of(0), extract(empty, suite, "psk_id_hash", empty), extract(empty, suite, "info_hash", context));
  const secret = extract(shared, suite, "secret", empty);
  const cipher = createCipheriv("chacha20-poly1305", expand(secret, suite, "key", schedule, 32), expand(secret, suite, "base_nonce", schedule, 12));
  cipher.setAAD(context);
  return { enc, ct: join(cipher.update(plaintext), cipher.final(), cipher.getAuthTag()) };
}

// Deterministic synthetic keys are confined to the independent known-answer generator.
const author = privateKey("70", Buffer.alloc(32, 7));
const recipientSigning = privateKey("70", Buffer.alloc(32, 8));
const recipientSecret = Buffer.alloc(32, 9);
const recipient = privateKey("6e", recipientSecret);
const ephemeral = privateKey("6e", Buffer.alloc(32, 13));
const plaintext = Buffer.alloc(32, 10);
const [organization, vault, authorAccount, authorMember, recipientAccount, recipientMember] = [1, 2, 3, 4, 5, 6].map(uuid);
const authorSigning = publicBytes(createPublicKey(author));
const recipientSigningBytes = publicBytes(createPublicKey(recipientSigning));
const recipientKem = publicBytes(createPublicKey(recipient));
const context = join(
  ascii("spl-shared-vault-wrap-v1"), Buffer.of(1, 2), uuidBytes(organization), uuidBytes(vault), integer(4, 8),
  uuidBytes(authorAccount), uuidBytes(authorMember), integer(8, 11), authorSigning,
  uuidBytes(recipientAccount), uuidBytes(recipientMember), integer(8, 12), recipientSigningBytes, recipientKem,
);
const { enc, ct } = hpke(context, recipient, plaintext, ephemeral);
const signature = sign(null, join(ascii("spl-shared-vault-wrap-signature-v1"), context, enc, ct), author);
const bytes = join(Buffer.of(1), enc, ct, signature);
const document = {
  format: "scoplen-test-vectors",
  version: 1,
  vectors: [{
    id: "crypto-shared-vault-admission-wrap-v1",
    kind: "crypto.shared-vault-wrap-open",
    input: [organization, vault, 8, authorAccount, authorMember, 11, toHex(authorSigning), recipientAccount,
      recipientMember, 12, toHex(recipientSigningBytes), toHex(recipientSecret), toHex(bytes)].join("|"),
    expected: toHex(plaintext),
  }],
};
const output = `${JSON.stringify(document, null, 2)}\n`;
const path = new URL("../vectors/shared-vault-wrap.json", import.meta.url);
if (process.argv.includes("--check")) {
  assert.equal((await readFile(path, "utf8")).replaceAll("\r\n", "\n"), output);
} else {
  await writeFile(path, output);
}
