// SPDX-License-Identifier: Apache-2.0
// Generated from v1.yaml by the Scoplen OpenAPI generator.

export interface components {
  schemas: {
    Resource: Resource;
    ResourcePage: ResourcePage;
    ProblemDetails: ProblemDetails;
    AuthChallengeRequest: AuthChallengeRequest;
    AuthChallengeResponse: AuthChallengeResponse;
    AuthDeviceRequest: AuthDeviceRequest;
    AuthTokenResponse: AuthTokenResponse;
    AuthRefreshRequest: AuthRefreshRequest;
    BrowserAuthRefreshRequest: BrowserAuthRefreshRequest;
    BrowserAuthTokenResponse: BrowserAuthTokenResponse;
    GatewayTicketRequest: GatewayTicketRequest;
    GatewayEdgeAddress: GatewayEdgeAddress;
    GatewayTicketResponse: GatewayTicketResponse;
    ListQuery: ListQuery;
    WriteRequest: WriteRequest;
    DecisionRequest: DecisionRequest;
    PolicyEvaluationRequest: PolicyEvaluationRequest;
    PolicyEvaluationResponse: PolicyEvaluationResponse;
    CertificateRequest: CertificateRequest;
    CertificateHostRequest: CertificateHostRequest;
    CertificateHostGroupRequest: CertificateHostGroupRequest;
    CertificateIssuanceResponse: CertificateIssuanceResponse;
    AccountProfile: AccountProfile;
    PersonalInvitationRequest: PersonalInvitationRequest;
    PersonalInvitationResponse: PersonalInvitationResponse;
    PersonalEnrollmentRequest: PersonalEnrollmentRequest;
    PersonalEnrollmentResponse: PersonalEnrollmentResponse;
    PersonalRateLimitedProblem: PersonalRateLimitedProblem;
    PersonalStorageUnavailableProblem: PersonalStorageUnavailableProblem;
    PersonalCommitOutcomeUnknownProblem: PersonalCommitOutcomeUnknownProblem;
    Account: Resource;
    Device: Resource;
    Organization: Resource;
    Member: Resource;
    Invitation: Resource;
    Group: Resource;
    IdentityProvider: Resource;
    ServicePrincipal: Resource;
    Host: Resource;
    AccessProfile: Resource;
    Route: Resource;
    HostGroup: Resource;
    Snippet: Resource;
    TrustRecord: Resource;
    GatewayNetwork: Resource;
    InventoryImport: Resource;
    Policy: Resource;
    Role: Resource;
    Grant: Resource;
    AccessRequest: Resource;
    AccessDecision: Resource;
    CertificateAuthority: Resource;
    Certificate: Resource;
    Gateway: Resource;
    JoinToken: Resource;
    Credential: Resource;
    HostAgent: Resource;
    Session: Resource;
    Recording: Resource;
    AuditEvent: Resource;
    AuditExport: Resource;
    Integration: Resource;
  };
}

export interface Resource {
  id: string;
  etag: string;
  created_at: string;
  updated_at: string;
  data: Record<string, unknown>;
}
export interface ResourcePage { items: Resource[]; next_cursor: string | null; }
// BEGIN GENERATED AccountProfile
export interface AccountProfile {
  id: string;
  etag: string;
  created_at: string;
  updated_at: string;
  data: AccountProfileData;
  [extension: string]: unknown;
}

export interface AccountProfileData {
  email: string | null;
  [extension: string]: unknown;
}
// END GENERATED AccountProfile
// BEGIN GENERATED PersonalEnrollment
export type PersonalInvitationRequest = Record<string, never>;

export interface PersonalInvitationResponse {
  invitation_url: string;
  expires_at: string;
  [extension: string]: unknown;
}

export interface PersonalEnrollmentRequest {
  invitation_token: string;
  account_id: string;
  personal_vault_id: string;
  account_signing_public_key: string;
  account_kem_public_key: string;
  key_bundle_update: string;
  device_certificate: string;
  wrapped_personal_vault_key: string;
  device_signature: string;
}

export interface PersonalEnrollmentResponse {
  account_id: string;
  device_id: string;
  personal_vault_id: string;
  [extension: string]: unknown;
}

export interface PersonalRateLimitHeaders {
  /** Decimal 1..300 seconds; RateLimit.t equals this delay. */
  "Retry-After": string;
  "RateLimit-Policy": '"personal";q=30;w=60';
  RateLimit: string;
  "Cache-Control": "no-store";
  Pragma: "no-cache";
  "Referrer-Policy": "no-referrer";
}

export type PersonalRateLimitedProblem = Omit<ProblemDetails, "status" | "code" | "changed" | "retryable"> & {
  status: 429;
  code: "auth.rate_limited";
  changed: false;
  retryable: true;
};

export type PersonalStorageUnavailableProblem = Omit<ProblemDetails, "status" | "code" | "changed" | "retryable"> & {
  status: 503;
  code: "auth.storage_unavailable";
  changed: false;
  retryable: true;
};

export type PersonalCommitOutcomeUnknownProblem = Omit<ProblemDetails, "status" | "code" | "changed" | "retryable"> & {
  status: 503;
  code: "auth.commit_outcome_unknown";
  changed: true;
  retryable: false;
};

export type PersonalStorageFailureProblem = PersonalStorageUnavailableProblem | PersonalCommitOutcomeUnknownProblem;
// END GENERATED PersonalEnrollment
// BEGIN GENERATED ProblemDetails
export interface ProblemDetails {
  type: string;
  title: string;
  status: number;
  detail: string;
  instance: string;
  code: string;
  /** False guarantees no business-state mutation from the failed operation; true means a mutation occurred or cannot be ruled out, not that success was established. Admission counters and failure-audit records are not business-state mutations. */
  changed: boolean;
  /** Whether the same request may safely be retried; false forbids automatic replay. */
  retryable: boolean;
  [extension: string]: unknown;
}
// END GENERATED ProblemDetails
// BEGIN GENERATED Authentication
export interface AuthChallengeRequest {
  device_id: string;
}

export interface AuthChallengeResponse {
  nonce: string;
  server_time: string;
  [extension: string]: unknown;
}

export interface AuthDeviceRequest {
  device_id: string;
  nonce: string;
  signature: string;
}

export interface AuthRefreshRequest {
  refresh_token: string;
}

export type BrowserAuthRefreshRequest = Record<string, never>;

export interface AuthTokenResponse {
  access_token: string;
  token_type: "DPoP";
  expires_in: number;
  refresh_token: string;
  refresh_expires_in: number;
  [extension: string]: unknown;
}

export interface BrowserAuthTokenResponse {
  access_token: string;
  token_type: "DPoP";
  expires_in: number;
  refresh_expires_in: number;
  refresh_token?: never;
  [extension: string]: unknown;
}
// END GENERATED Authentication
// BEGIN GENERATED GatewayTicket
export interface GatewayTicketRequest {
  host: string;
  remote_user: string;
  ssh_public_key: string;
}

export interface GatewayEdgeAddress {
  host: string;
  port: number;
  [extension: string]: unknown;
}

export interface GatewayTicketResponse {
  ticket: string;
  edge_addresses: GatewayEdgeAddress[];
  gateway_host_ca_public_key: string;
  [extension: string]: unknown;
}
// END GENERATED GatewayTicket
export interface ListQuery { limit?: number; cursor?: string; filter?: string; sort?: string; }
export interface WriteRequest { data: Record<string, unknown>; }
export interface DecisionRequest { decision: "approve" | "deny"; reason?: string; }
export interface PolicyEvaluationRequest { action: string; resource: Record<string, unknown>; context: Record<string, unknown>; }
export interface PolicyEvaluationResponse { decision: "allow" | "deny"; policies: string[]; }
// BEGIN GENERATED CertificateRequest
export interface CertificateHostRequest {
  public_key: string;
  hosts: string[];
  host_groups?: never;
  remote_user: string;
  ttl_seconds: number;
}

export interface CertificateHostGroupRequest {
  public_key: string;
  host_groups: string[];
  hosts?: never;
  remote_user: string;
  ttl_seconds: number;
}

export type CertificateRequest = CertificateHostRequest | CertificateHostGroupRequest;
// END GENERATED CertificateRequest
// BEGIN GENERATED CertificateIssuanceResponse
export interface CertificateIssuanceResponse {
  id: string;
  etag: string;
  created_at: string;
  updated_at: string;
  data: CertificateIssuanceData;
  [extension: string]: unknown;
}

export interface CertificateIssuanceData {
  certificate: string;
  [extension: string]: unknown;
}
// END GENERATED CertificateIssuanceResponse

export interface paths {
  [path: string]: {
    get?: unknown; post?: unknown; patch?: unknown; delete?: unknown;
  };
}
