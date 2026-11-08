// SPDX-License-Identifier: Apache-2.0
import type {
  AccountBrowserPasswordLoginResponse,
  AccountBrowserRefreshResponse,
} from "./index";

declare const refresh: AccountBrowserRefreshResponse;
declare const login: AccountBrowserPasswordLoginResponse;

const access: `ab1_${string}` = refresh.access_token;
const scheme: "DPoP" = refresh.token_type;
const accessSeconds: 600 = refresh.expires_in;
const familySeconds: number = refresh.refresh_expires_in;
const initialFamilySeconds: 2592000 = login.refresh_expires_in;
const extension: unknown = refresh.future_extension;
const nativeRefresh: undefined = refresh.refresh_token;
const admission: undefined = refresh.admission_token;
const bootstrap: undefined = refresh.snapshot;

const session: AccountBrowserRefreshResponse = {
  access_token: "ab1_example",
  token_type: "DPoP",
  expires_in: 600,
  refresh_expires_in: 3600,
  future_extension: true,
};

// @ts-expect-error A browser session still requires its token type.
const missingScheme: AccountBrowserRefreshResponse = { access_token: "ab1_example", expires_in: 600, refresh_expires_in: 3600 };
// @ts-expect-error Refresh lifetime remains a required numeric field.
const missingLifetime: AccountBrowserRefreshResponse = { access_token: "ab1_example", token_type: "DPoP", expires_in: 600 };
// @ts-expect-error Native refresh credentials cannot appear in a browser session.
const nativeSession: AccountBrowserRefreshResponse = { ...session, refresh_token: "native" };
// @ts-expect-error Admission capabilities cannot appear in a browser session.
const admissionSession: AccountBrowserRefreshResponse = { ...session, admission_token: "native" };
// @ts-expect-error Browser sessions carry the DPoP token type.
const bearerSession: AccountBrowserRefreshResponse = { ...session, token_type: "Bearer" };
// @ts-expect-error The login response has the full initial family lifetime.
const shortLogin: AccountBrowserPasswordLoginResponse = { ...session, refresh_expires_in: 3600 };

void [access, scheme, accessSeconds, familySeconds, initialFamilySeconds, extension,
  nativeRefresh, admission, bootstrap, session, missingScheme, missingLifetime,
  nativeSession, admissionSession, bearerSession, shortLogin];
