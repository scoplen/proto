// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { accountBrowserDefinitions, generateAccountBrowserTypes, initialAccountBrowserScope } from "./generate-account-browser.mjs";

const authored = JSON.parse(await readFile(new URL("v1.yaml", import.meta.url), "utf8"));

test("D-140 exact four endpoints reuse shared shapes and independent principal", async () => {
  const expected = accountBrowserDefinitions();
  assert.equal(Object.keys(expected.paths).length, 4);
  assert.equal(expected.operations.length, 45);
  assert.equal(new Set(expected.operations.map(({ method, path }) => `${method} ${path}`)).size, 45);
  const types = generateAccountBrowserTypes(authored);
  assert.match(types, /AccountBrowserPasswordLoginRequest = AccountPasswordLoginRequest/);
  assert.match(types, /AccountBrowserLogoutResponse = OperatorLogoutResponse/);
  const index = await readFile(new URL("index.ts", import.meta.url), "utf8");
  const declarations = await readFile(new URL("types.ts", import.meta.url), "utf8");
  for (const name of ["AccountBrowserPasswordOptionsRequest", "AccountBrowserPasswordOptionsResponse", "AccountBrowserPasswordLoginRequest", "AccountBrowserPasswordLoginResponse", "AccountBrowserRefreshRequest", "AccountBrowserRefreshResponse", "AccountBrowserLogoutRequest", "AccountBrowserLogoutResponse", "initialAccountBrowserScope", "accountBrowserOperations"]) assert.ok(index.includes(name), `public export ${name}`);
  for (const name of Object.keys(expected.schemas)) assert.ok(declarations.includes(`${name}: ${name};`), `components schema ${name}`);
  assert.equal(initialAccountBrowserScope.split(" ").length, 10);
  for (const kind of ["trust-records", "snippets", "gateway-networks", "certificate-authorities", "certificates", "/sync/", "/admin/", "devices"]) assert.ok(expected.operations.every(operation => !operation.path.includes(kind)));
  assert.equal(expected.operations.filter(operation => operation.writerReceipt).length, 6);
});

test("D-140 generator rejects byte limits, profile, cookie, scopes and writer drift", () => {
  for (const mutate of [
    d => { d.paths["/auth/accounts/browser/refresh"].post["x-scoplen-request-max-bytes"] = 4096; },
    d => { d.components.schemas.AccountBrowserRefreshResponse.allOf[1].properties.expires_in.const = 601; },
    d => { d.components.schemas.AccountBrowserRefreshResponse.allOf[1].not.anyOf.pop(); },
    d => { delete d.paths["/auth/accounts/browser/password/login"].post.responses["200"].headers["Set-Cookie"]; },
    d => { d["x-scoplen-account-browser-operations"][0].scopes = ["keys:read"]; },
    d => { d["x-scoplen-account-browser-operations"].find(operation => operation.writerReceipt).writerReceipt = false; },
    d => { delete d.components.securitySchemes.accountBrowserAccess; },
    d => { delete d.paths["/orgs/{org}/hosts"].get; },
  ]) {
    const copy = structuredClone(authored); mutate(copy);
    assert.throws(() => generateAccountBrowserTypes(copy), /D-140/);
  }
});
