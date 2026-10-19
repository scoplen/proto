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
    CertificateResponse: CertificateResponse;
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
// BEGIN GENERATED ProblemDetails
export interface ProblemDetails {
  type: string;
  title: string;
  status: number;
  detail: string;
  instance: string;
  code: string;
  changed: boolean;
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
export interface CertificateRequest { public_key: string; hosts?: string[]; host_groups?: string[]; remote_user: string; ttl_seconds: number; }
export interface CertificateResponse { certificate: string; valid_after: string; valid_before: string; }

export interface paths {
  [path: string]: {
    get?: unknown; post?: unknown; patch?: unknown; delete?: unknown;
  };
}
