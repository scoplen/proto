// SPDX-License-Identifier: Apache-2.0
import init, {
  derivePasswordAuth, generateTeamInvitation, parseTeamInvitationPassword,
  teamInvitationVerifier, generateSimpleRule,
} from "/pkg/scoplen_browser.js";

const bytes = hex => Uint8Array.from(hex.match(/../g) || [], pair => Number.parseInt(pair, 16));
const hex = value => Array.from(value, byte => byte.toString(16).padStart(2, "0")).join("");
const check = (condition, label) => { if (!condition) throw new Error(label); };
function rejected(action, pattern) {
  try { action(); }
  catch (error) {
    if (pattern) check(pattern.test(String(error)), "Wrong input-free failure class");
    return;
  }
  throw new Error("Expected shared-contract rejection");
}

function derive(context, password) {
  const output = new Uint8Array(32);
  try {
    derivePasswordAuth(context.origin, context.username, context.profile, bytes(context.salt), password, output);
    return hex(output);
  } finally {
    password.fill(0);
    output.fill(0);
  }
}

async function vectors(name) {
  const response = await fetch(`/vectors/${name}.json`, { credentials: "omit", redirect: "error" });
  check(response.ok, "Published vector document is unavailable");
  return (await response.json()).vectors;
}

async function run(mode) {
  await init();
  const passwordVectors = await vectors("password-bootstrap");
  const known = passwordVectors.find(vector => vector.kind === "crypto.password-bootstrap");
  const context = JSON.parse(known.input);
  const expected = JSON.parse(known.expected);
  if (mode === "resource") {
    rejected(() => derive(context, bytes(context.password_hex)), /resource failure/);
    return { ok: true, mode, allocationFailure: true };
  }
  if (mode === "randomness") {
    Object.defineProperty(globalThis.crypto, "getRandomValues", {
      configurable: true, value() { throw new Error("Injected CSPRNG failure"); },
    });
    const password = new Uint8Array(8);
    const verifier = new Uint8Array(32);
    try {
      rejected(() => generateTeamInvitation(context.origin, context.account_id, context.personal_vault_id, password, verifier), /randomness/);
      check(password.every(byte => byte === 0) && verifier.every(byte => byte === 0), "Random failure returned partial output");
      return { ok: true, mode, randomnessFailure: true };
    } finally { password.fill(0); verifier.fill(0); }
  }
  check(mode === "full", "Unknown browser test mode");
  check(derive(context, bytes(context.password_hex)) === expected.auth_secret, "Native password answer differs in WebAssembly");
  let normalizations = 0;
  for (const vector of passwordVectors.filter(vector => vector.kind === "crypto.password-normalization")) {
    if (vector.expected === "reject") rejected(() => derive(context, bytes(vector.input)));
    else check(derive(context, bytes(vector.input)) === derive(context, bytes(vector.expected)), "Native normalization answer differs in WebAssembly");
    normalizations += 1;
  }
  for (const change of [{ origin: "https://other.example.com" }, { username: "bob" }, { salt: "05".repeat(16) }]) {
    check(derive({ ...context, ...change }, bytes(context.password_hex)) !== expected.auth_secret, "Password context substitution retained the secret");
  }
  for (const change of [{ profile: 2 }, { salt: "00".repeat(15) }, { origin: "https://control.example.com/" }, { username: "Alice" }]) {
    rejected(() => derive({ ...context, ...change }, bytes(context.password_hex)));
  }
  for (const profile of [257, 1.5, Number.NaN, Number.POSITIVE_INFINITY, 2 ** 32 + 1]) {
    rejected(() => derive({ ...context, profile }, bytes(context.password_hex)), /unsupported password bootstrap profile/);
  }
  rejected(() => derive(context, new Uint8Array([0xff, 0xff])));
  const invalidOutput = new Uint8Array(31);
  const ownedPassword = bytes(context.password_hex);
  try { rejected(() => derivePasswordAuth(context.origin, context.username, 1, bytes(context.salt), ownedPassword, invalidOutput)); }
  finally { ownedPassword.fill(0); invalidOutput.fill(0); }

  let invitations = 0;
  for (const vector of await vectors("team-invitation")) {
    if (vector.kind === "crypto.team-invitation.password") {
      const password = bytes(vector.input);
      try {
        if (vector.expected === "reject") rejected(() => parseTeamInvitationPassword(password));
        else parseTeamInvitationPassword(password);
      } finally { password.fill(0); }
    } else {
      const input = JSON.parse(vector.input);
      const password = bytes(input.password_hex);
      const output = new Uint8Array(32);
      try {
        const action = () => teamInvitationVerifier(input.origin, input.organization_id, input.invitation_id, password, output);
        if (vector.expected === "reject") rejected(action);
        else { action(); check(hex(output) === vector.expected, "Native invitation answer differs in WebAssembly"); }
      } finally { password.fill(0); output.fill(0); }
    }
    invitations += 1;
  }
  const first = new Uint8Array(8);
  const second = new Uint8Array(8);
  const verifier = new Uint8Array(32);
  const reconstructed = new Uint8Array(32);
  try {
    generateTeamInvitation(context.origin, context.account_id, context.personal_vault_id, first, verifier);
    generateTeamInvitation(context.origin, context.account_id, context.personal_vault_id, second, reconstructed);
    check(hex(first) !== hex(second), "Independent generated invitations repeated");
    parseTeamInvitationPassword(first);
    teamInvitationVerifier(context.origin, context.account_id, context.personal_vault_id, first, reconstructed);
    check(hex(verifier) === hex(reconstructed), "Generated invitation verifier differs from shared parsing");
  } finally { first.fill(0); second.fill(0); verifier.fill(0); reconstructed.fill(0); }

  let rules = 0;
  for (const vector of (await vectors("group-policy")).filter(vector => ["group_policy.simple_input", "group_policy.simple_source"].includes(vector.kind))) {
    const input = new TextEncoder().encode(vector.input);
    if (vector.expected === "rejected") rejected(() => generateSimpleRule(input));
    else {
      const source = generateSimpleRule(input);
      if (vector.kind === "group_policy.simple_source") check(source === vector.expected, "Native Cedar source differs in WebAssembly");
    }
    rules += 1;
  }
  check(normalizations === 18 && invitations === 34 && rules === 28, "Published fixture coverage changed");
  return { ok: true, mode, passwordKnownAnswer: true, normalizations, invitations, rules, secretByteBuffersCleared: true };
}

self.onmessage = async event => {
  try { self.postMessage(await run(event.data.mode)); }
  catch { self.postMessage({ ok: false, error: "Shared browser contract check failed" }); }
  finally { self.close(); }
};
