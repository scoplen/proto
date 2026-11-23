// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { accountBrowserDefinitions, generateAccountBrowserTypes, initialAccountBrowserScope } from "./generate-account-browser.mjs";

const authored = JSON.parse(await readFile(new URL("v1.yaml", import.meta.url), "utf8"));

test("D-140 exact four endpoints reuse shared shapes and independent principal", async () => {
  const expected = accountBrowserDefinitions();
  assert.equal(Object.keys(expected.paths).length, 4);
  assert.equal(expected.operations.length, 69);
  assert.equal(new Set(expected.operations.map(({ method, path }) => `${method} ${path}`)).size, 69);
  const types = generateAccountBrowserTypes(authored);
  assert.match(types, /AccountBrowserPasswordLoginRequest = AccountPasswordLoginRequest/);
  assert.match(types, /AccountBrowserLogoutResponse = OperatorLogoutResponse/);
  const index = await readFile(new URL("index.ts", import.meta.url), "utf8");
  const declarations = await readFile(new URL("types.ts", import.meta.url), "utf8");
  for (const name of ["AccountBrowserPasswordOptionsRequest", "AccountBrowserPasswordOptionsResponse", "AccountBrowserPasswordLoginRequest", "AccountBrowserPasswordLoginResponse", "AccountBrowserRefreshRequest", "AccountBrowserRefreshResponse", "AccountBrowserLogoutRequest", "AccountBrowserLogoutResponse", "initialAccountBrowserScope", "accountBrowserOperations"]) assert.ok(index.includes(name), `public export ${name}`);
  for (const name of Object.keys(expected.schemas)) assert.ok(declarations.includes(`${name}: ${name};`), `components schema ${name}`);
  assert.equal(initialAccountBrowserScope.split(" ").length, 16);
  assert.equal(authored.paths["/auth/accounts/browser/password/login"].post["x-scoplen-initial-browser-scope"], initialAccountBrowserScope);
  const refresh = authored.paths["/auth/accounts/browser/refresh"].post;
  assert.equal(refresh["x-scoplen-initial-browser-scope"], undefined);
  assert.equal(refresh["x-scoplen-refresh-scope-ceiling"], "original-family");
  for (const kind of ["trust-records", "gateway-networks", "certificate-authorities", "certificates", "/sync/", "/admin/", "devices"]) assert.ok(expected.operations.every(operation => !operation.path.includes(kind)));
  assert.equal(expected.operations.filter(operation => operation.writerReceipt).length, 14);
});

test("D-155 adds exactly five existing Snippet routes with unchanged inventory scopes", () => {
  const { operations } = accountBrowserDefinitions();
  assert.deepEqual(operations.filter(operation => operation.path.includes("/snippets")), [
    { method: "GET", path: "/api/v1/orgs/{org}/snippets", scopes: ["inventory:read"], writerReceipt: false },
    { method: "GET", path: "/api/v1/orgs/{org}/snippets/{id}", scopes: ["inventory:read"], writerReceipt: false },
    { method: "POST", path: "/api/v1/orgs/{org}/snippets", scopes: ["inventory:write"], writerReceipt: true },
    { method: "PUT", path: "/api/v1/orgs/{org}/snippets/{id}", scopes: ["inventory:write"], writerReceipt: false },
    { method: "DELETE", path: "/api/v1/orgs/{org}/snippets/{id}", scopes: ["inventory:write"], writerReceipt: false },
  ]);
  assert.equal(initialAccountBrowserScope, "access-requests:decide access-requests:read access-requests:write account:read audit:read auth-drafts:manage auth-test:run inventory:read inventory:write orgs:create orgs:read orgs:write policies:read policies:write teams:join teams:manage");
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
    d => { delete d.paths["/orgs/{org}/snippets"].post; },
    d => { delete d.paths["/orgs/{org}/snippets/{id}"].put; },
    d => { d["x-scoplen-account-browser-operations"].find(operation => operation.path.endsWith("/snippets") && operation.method === "POST").writerReceipt = false; },
  ]) {
    const copy = structuredClone(authored); mutate(copy);
    assert.throws(() => generateAccountBrowserTypes(copy), /D-140/);
  }
});
