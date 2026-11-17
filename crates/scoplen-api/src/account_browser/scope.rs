// SPDX-License-Identifier: Apache-2.0
//! Independent D-140 router-owned browser permissions; unmapped operations fail closed.

use scoplen_model::validate_uuid_v7;
use uuid::Uuid;

use super::AccountBrowserCodecError;

/// Exact initial browser ceiling in byte order; never current membership or Cedar authority.
pub const INITIAL_ACCOUNT_BROWSER_ACCESS_SCOPE: &str = "access-requests:decide access-requests:read access-requests:write account:read audit:read inventory:read inventory:write orgs:create orgs:read orgs:write policies:read policies:write teams:join teams:manage";

/// Registered coarse browser permissions, independent of Device/Operator registries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountBrowserAccessScope {
    /// Decide a currently routed non-self access request.
    AccessRequestsDecide,
    /// Read own or currently routed access requests.
    AccessRequestsRead,
    /// Check, create or cancel the caller's access request.
    AccessRequestsWrite,
    /// Exact `account:read` browser permission.
    AccountRead,
    /// Exact `audit:read` browser permission; current `view_audit` remains mandatory.
    AuditRead,
    /// Exact `inventory:read` browser permission.
    InventoryRead,
    /// Exact `inventory:write` browser permission.
    InventoryWrite,
    /// Exact `orgs:create` browser permission.
    OrganizationCreate,
    /// Exact `orgs:read` browser permission.
    OrganizationRead,
    /// Exact `orgs:write` browser permission.
    OrganizationWrite,
    /// Exact `policies:read` browser permission.
    PoliciesRead,
    /// Exact `policies:write` browser permission.
    PoliciesWrite,
    /// Exact `teams:join` browser permission.
    TeamsJoin,
    /// Exact `teams:manage` browser permission.
    TeamsManage,
}

impl AccountBrowserAccessScope {
    /// Every scope in canonical byte order.
    pub const ALL: [Self; 14] = [
        Self::AccessRequestsDecide,
        Self::AccessRequestsRead,
        Self::AccessRequestsWrite,
        Self::AccountRead,
        Self::AuditRead,
        Self::InventoryRead,
        Self::InventoryWrite,
        Self::OrganizationCreate,
        Self::OrganizationRead,
        Self::OrganizationWrite,
        Self::PoliciesRead,
        Self::PoliciesWrite,
        Self::TeamsJoin,
        Self::TeamsManage,
    ];
    /// Exact case-sensitive scope token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AccessRequestsDecide => "access-requests:decide",
            Self::AccessRequestsRead => "access-requests:read",
            Self::AccessRequestsWrite => "access-requests:write",
            Self::AccountRead => "account:read",
            Self::AuditRead => "audit:read",
            Self::InventoryRead => "inventory:read",
            Self::InventoryWrite => "inventory:write",
            Self::OrganizationCreate => "orgs:create",
            Self::OrganizationRead => "orgs:read",
            Self::OrganizationWrite => "orgs:write",
            Self::PoliciesRead => "policies:read",
            Self::PoliciesWrite => "policies:write",
            Self::TeamsJoin => "teams:join",
            Self::TeamsManage => "teams:manage",
        }
    }
    /// Recognize only an explicit browser scope, with no wildcard or alias.
    #[must_use]
    pub fn from_token(token: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|scope| scope.as_str() == token)
    }
    /// Check exact membership in a verified, stored scope ceiling.
    #[must_use]
    pub fn is_present_in(self, verified_scope: &str) -> bool {
        verified_scope.split(' ').any(|token| token == self.as_str())
    }
}

/// The explicit initial browser operation whitelist; a scope alone cannot add routes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountBrowserAccessOperation {
    /// `POST /api/v1/orgs/{org}/access-requests/check`.
    AccessRequestCheck,
    /// `POST /api/v1/orgs/{org}/access-requests`.
    AccessRequestCreate,
    /// `GET /api/v1/orgs/{org}/access-requests`.
    AccessRequestList,
    /// `GET /api/v1/orgs/{org}/access-requests/{id}`.
    AccessRequestRead,
    /// `POST /api/v1/orgs/{org}/access-requests/{id}/decisions`.
    AccessRequestDecide,
    /// `POST /api/v1/orgs/{org}/access-requests/{id}/cancel`.
    AccessRequestCancel,
    /// `GET /api/v1/accounts/me`.
    AccountProfileRead,
    /// `GET /api/v1/orgs/{org}/audit-events`.
    AuditEventList,
    /// `GET /api/v1/orgs/{org}/audit-events/verify`.
    AuditRangeVerify,
    /// `POST /api/v1/orgs`.
    OrganizationCreate,
    /// `GET /api/v1/orgs`.
    OrganizationList,
    /// `GET /api/v1/orgs/{org}`.
    OrganizationRead,
    /// `PATCH /api/v1/orgs/{org}`.
    OrganizationUpdate,
    /// `POST /api/v1/orgs/{org}/invitations`.
    TeamInvitationCreate,
    /// `GET /api/v1/orgs/{org}/invitations`.
    TeamInvitationList,
    /// `GET /api/v1/orgs/{org}/invitations/{invitation}`.
    TeamInvitationRead,
    /// `POST /api/v1/orgs/{org}/invitations/{invitation}/accept`.
    TeamInvitationAccept,
    /// `DELETE /api/v1/orgs/{org}/invitations/{invitation}`.
    TeamInvitationRevoke,
    /// `GET /api/v1/orgs/{org}/members`.
    TeamMemberList,
    /// `GET /api/v1/orgs/{org}/members/{membership}`.
    TeamMemberRead,
    /// `PATCH /api/v1/orgs/{org}/members/{membership}`.
    TeamMemberUpdate,
    /// `DELETE /api/v1/orgs/{org}/members/{membership}`.
    TeamMemberRemove,
    /// `POST /api/v1/orgs/{org}/dissolve`.
    TeamDissolve,
    /// `GET /api/v1/orgs/{org}/hosts`.
    InventoryHostList,
    /// Atomic initial Organization Host/default-Login CSV batch.
    InventoryImportCreate,
    /// `GET /api/v1/orgs/{org}/hosts/{id}`.
    InventoryHostRead,
    /// `POST /api/v1/orgs/{org}/hosts`.
    InventoryHostCreate,
    /// `PUT /api/v1/orgs/{org}/hosts/{id}`.
    InventoryHostReplace,
    /// `DELETE /api/v1/orgs/{org}/hosts/{id}`.
    InventoryHostDelete,
    /// `GET /api/v1/orgs/{org}/host-groups`.
    InventoryHostGroupList,
    /// `GET /api/v1/orgs/{org}/host-groups/{id}`.
    InventoryHostGroupRead,
    /// `POST /api/v1/orgs/{org}/host-groups`.
    InventoryHostGroupCreate,
    /// `PUT /api/v1/orgs/{org}/host-groups/{id}`.
    InventoryHostGroupReplace,
    /// `DELETE /api/v1/orgs/{org}/host-groups/{id}`.
    InventoryHostGroupDelete,
    /// `GET /api/v1/orgs/{org}/access-profiles`.
    InventoryAccessProfileList,
    /// `GET /api/v1/orgs/{org}/access-profiles/{id}`.
    InventoryAccessProfileRead,
    /// `POST /api/v1/orgs/{org}/access-profiles`.
    InventoryAccessProfileCreate,
    /// `PUT /api/v1/orgs/{org}/access-profiles/{id}`.
    InventoryAccessProfileReplace,
    /// `DELETE /api/v1/orgs/{org}/access-profiles/{id}`.
    InventoryAccessProfileDelete,
    /// `GET /api/v1/orgs/{org}/routes`.
    InventoryRouteList,
    /// `GET /api/v1/orgs/{org}/routes/{id}`.
    InventoryRouteRead,
    /// `POST /api/v1/orgs/{org}/routes`.
    InventoryRouteCreate,
    /// `PUT /api/v1/orgs/{org}/routes/{id}`.
    InventoryRouteReplace,
    /// `DELETE /api/v1/orgs/{org}/routes/{id}`.
    InventoryRouteDelete,
    /// `GET /api/v1/orgs/{org}/snippets`.
    InventorySnippetList,
    /// `GET /api/v1/orgs/{org}/snippets/{id}`.
    InventorySnippetRead,
    /// `POST /api/v1/orgs/{org}/snippets`.
    InventorySnippetCreate,
    /// `PUT /api/v1/orgs/{org}/snippets/{id}`.
    InventorySnippetReplace,
    /// `DELETE /api/v1/orgs/{org}/snippets/{id}`.
    InventorySnippetDelete,
    /// `GET /api/v1/orgs/{org}/groups`.
    OrganizationGroupList,
    /// `GET /api/v1/orgs/{org}/groups/{id}`.
    OrganizationGroupRead,
    /// `POST /api/v1/orgs/{org}/groups`.
    OrganizationGroupCreate,
    /// `PUT /api/v1/orgs/{org}/groups/{id}`.
    OrganizationGroupReplace,
    /// `DELETE /api/v1/orgs/{org}/groups/{id}`.
    OrganizationGroupDelete,
    /// `GET /api/v1/orgs/{org}/policies`.
    OrganizationPolicyList,
    /// `GET /api/v1/orgs/{org}/policies/{id}`.
    OrganizationPolicyRead,
    /// `POST /api/v1/orgs/{org}/policies`.
    OrganizationPolicyCreate,
    /// `PUT /api/v1/orgs/{org}/policies/{id}`.
    OrganizationPolicyReplace,
    /// `DELETE /api/v1/orgs/{org}/policies/{id}`.
    OrganizationPolicyDelete,
    /// `GET /api/v1/orgs/{org}/grants`.
    OrganizationGrantList,
    /// `GET /api/v1/orgs/{org}/grants/{id}`.
    OrganizationGrantRead,
    /// `POST /api/v1/orgs/{org}/grants`.
    OrganizationGrantCreate,
    /// `PUT /api/v1/orgs/{org}/grants/{id}`.
    OrganizationGrantReplace,
    /// `DELETE /api/v1/orgs/{org}/grants/{id}`.
    OrganizationGrantDelete,
    /// Authenticated self-family termination, never anonymous access.
    Logout,
}

/// Distinguishes business scope checks from intrinsic authenticated logout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountBrowserAccessRequirement {
    /// At least one scope plus current Account/Membership/Cedar authority.
    AnyScope(&'static [AccountBrowserAccessScope]),
    /// Only the original current-family terminal logout boundary.
    SelfSessionTermination,
}

impl AccountBrowserAccessOperation {
    /// Every operation in this finite browser registry.
    pub const ALL: [Self; 65] = [
        Self::AccessRequestCheck,
        Self::AccessRequestCreate,
        Self::AccessRequestList,
        Self::AccessRequestRead,
        Self::AccessRequestDecide,
        Self::AccessRequestCancel,
        Self::AccountProfileRead,
        Self::AuditEventList,
        Self::AuditRangeVerify,
        Self::OrganizationCreate,
        Self::OrganizationList,
        Self::OrganizationRead,
        Self::OrganizationUpdate,
        Self::TeamInvitationCreate,
        Self::TeamInvitationList,
        Self::TeamInvitationRead,
        Self::TeamInvitationAccept,
        Self::TeamInvitationRevoke,
        Self::TeamMemberList,
        Self::TeamMemberRead,
        Self::TeamMemberUpdate,
        Self::TeamMemberRemove,
        Self::TeamDissolve,
        Self::InventoryHostList,
        Self::InventoryImportCreate,
        Self::InventoryHostRead,
        Self::InventoryHostCreate,
        Self::InventoryHostReplace,
        Self::InventoryHostDelete,
        Self::InventoryHostGroupList,
        Self::InventoryHostGroupRead,
        Self::InventoryHostGroupCreate,
        Self::InventoryHostGroupReplace,
        Self::InventoryHostGroupDelete,
        Self::InventoryAccessProfileList,
        Self::InventoryAccessProfileRead,
        Self::InventoryAccessProfileCreate,
        Self::InventoryAccessProfileReplace,
        Self::InventoryAccessProfileDelete,
        Self::InventoryRouteList,
        Self::InventoryRouteRead,
        Self::InventoryRouteCreate,
        Self::InventoryRouteReplace,
        Self::InventoryRouteDelete,
        Self::InventorySnippetList,
        Self::InventorySnippetRead,
        Self::InventorySnippetCreate,
        Self::InventorySnippetReplace,
        Self::InventorySnippetDelete,
        Self::OrganizationGroupList,
        Self::OrganizationGroupRead,
        Self::OrganizationGroupCreate,
        Self::OrganizationGroupReplace,
        Self::OrganizationGroupDelete,
        Self::OrganizationPolicyList,
        Self::OrganizationPolicyRead,
        Self::OrganizationPolicyCreate,
        Self::OrganizationPolicyReplace,
        Self::OrganizationPolicyDelete,
        Self::OrganizationGrantList,
        Self::OrganizationGrantRead,
        Self::OrganizationGrantCreate,
        Self::OrganizationGrantReplace,
        Self::OrganizationGrantDelete,
        Self::Logout,
    ];
    /// Exact authenticated requirement; neither branch establishes authority.
    #[must_use]
    pub const fn requirement(self) -> AccountBrowserAccessRequirement {
        match self {
            Self::AccessRequestCheck | Self::AccessRequestCreate | Self::AccessRequestCancel => {
                AccountBrowserAccessRequirement::AnyScope(&[
                    AccountBrowserAccessScope::AccessRequestsWrite,
                ])
            }
            Self::AccessRequestList | Self::AccessRequestRead => {
                AccountBrowserAccessRequirement::AnyScope(&[
                    AccountBrowserAccessScope::AccessRequestsRead,
                ])
            }
            Self::AccessRequestDecide => AccountBrowserAccessRequirement::AnyScope(&[
                AccountBrowserAccessScope::AccessRequestsDecide,
            ]),
            Self::AuditEventList | Self::AuditRangeVerify => {
                AccountBrowserAccessRequirement::AnyScope(&[AccountBrowserAccessScope::AuditRead])
            }
            Self::AccountProfileRead => {
                AccountBrowserAccessRequirement::AnyScope(&[AccountBrowserAccessScope::AccountRead])
            }
            Self::OrganizationCreate => AccountBrowserAccessRequirement::AnyScope(&[
                AccountBrowserAccessScope::OrganizationCreate,
            ]),
            Self::OrganizationList | Self::OrganizationRead => {
                AccountBrowserAccessRequirement::AnyScope(&[
                    AccountBrowserAccessScope::OrganizationRead,
                ])
            }
            Self::OrganizationUpdate => AccountBrowserAccessRequirement::AnyScope(&[
                AccountBrowserAccessScope::OrganizationWrite,
            ]),
            Self::TeamInvitationCreate
            | Self::TeamInvitationList
            | Self::TeamInvitationRevoke
            | Self::TeamMemberList
            | Self::TeamMemberRead
            | Self::TeamMemberUpdate
            | Self::TeamDissolve
            | Self::OrganizationGroupCreate
            | Self::OrganizationGroupReplace
            | Self::OrganizationGroupDelete => {
                AccountBrowserAccessRequirement::AnyScope(&[AccountBrowserAccessScope::TeamsManage])
            }
            Self::TeamInvitationRead | Self::TeamMemberRemove => {
                AccountBrowserAccessRequirement::AnyScope(&[
                    AccountBrowserAccessScope::TeamsJoin,
                    AccountBrowserAccessScope::TeamsManage,
                ])
            }
            Self::TeamInvitationAccept => {
                AccountBrowserAccessRequirement::AnyScope(&[AccountBrowserAccessScope::TeamsJoin])
            }
            Self::InventoryHostList
            | Self::InventoryHostRead
            | Self::InventoryHostGroupList
            | Self::InventoryHostGroupRead
            | Self::InventoryAccessProfileList
            | Self::InventoryAccessProfileRead
            | Self::InventoryRouteList
            | Self::InventoryRouteRead
            | Self::InventorySnippetList
            | Self::InventorySnippetRead => AccountBrowserAccessRequirement::AnyScope(&[
                AccountBrowserAccessScope::InventoryRead,
            ]),
            Self::InventoryImportCreate
            | Self::InventoryHostCreate
            | Self::InventoryHostReplace
            | Self::InventoryHostDelete
            | Self::InventoryHostGroupCreate
            | Self::InventoryHostGroupReplace
            | Self::InventoryHostGroupDelete
            | Self::InventoryAccessProfileCreate
            | Self::InventoryAccessProfileReplace
            | Self::InventoryAccessProfileDelete
            | Self::InventoryRouteCreate
            | Self::InventoryRouteReplace
            | Self::InventoryRouteDelete
            | Self::InventorySnippetCreate
            | Self::InventorySnippetReplace
            | Self::InventorySnippetDelete => AccountBrowserAccessRequirement::AnyScope(&[
                AccountBrowserAccessScope::InventoryWrite,
            ]),
            Self::OrganizationGroupList
            | Self::OrganizationGroupRead
            | Self::OrganizationPolicyList
            | Self::OrganizationPolicyRead
            | Self::OrganizationGrantList
            | Self::OrganizationGrantRead => AccountBrowserAccessRequirement::AnyScope(&[
                AccountBrowserAccessScope::PoliciesRead,
            ]),
            Self::OrganizationPolicyCreate
            | Self::OrganizationPolicyReplace
            | Self::OrganizationPolicyDelete
            | Self::OrganizationGrantCreate
            | Self::OrganizationGrantReplace
            | Self::OrganizationGrantDelete => AccountBrowserAccessRequirement::AnyScope(&[
                AccountBrowserAccessScope::PoliciesWrite,
            ]),
            Self::Logout => AccountBrowserAccessRequirement::SelfSessionTermination,
        }
    }
    /// Canonical HTTP method.
    #[must_use]
    pub const fn http_method(self) -> &'static str {
        match self {
            Self::AccessRequestList
            | Self::AccessRequestRead
            | Self::AuditEventList
            | Self::AuditRangeVerify
            | Self::AccountProfileRead
            | Self::OrganizationList
            | Self::OrganizationRead
            | Self::TeamInvitationList
            | Self::TeamInvitationRead
            | Self::TeamMemberList
            | Self::TeamMemberRead
            | Self::InventoryHostList
            | Self::InventoryHostRead
            | Self::InventoryHostGroupList
            | Self::InventoryHostGroupRead
            | Self::InventoryAccessProfileList
            | Self::InventoryAccessProfileRead
            | Self::InventoryRouteList
            | Self::InventoryRouteRead
            | Self::InventorySnippetList
            | Self::InventorySnippetRead
            | Self::OrganizationGroupList
            | Self::OrganizationGroupRead
            | Self::OrganizationPolicyList
            | Self::OrganizationPolicyRead
            | Self::OrganizationGrantList
            | Self::OrganizationGrantRead => "GET",
            Self::AccessRequestCheck
            | Self::AccessRequestCreate
            | Self::AccessRequestDecide
            | Self::AccessRequestCancel
            | Self::OrganizationCreate
            | Self::TeamInvitationCreate
            | Self::TeamInvitationAccept
            | Self::TeamDissolve
            | Self::InventoryImportCreate
            | Self::InventoryHostCreate
            | Self::InventoryHostGroupCreate
            | Self::InventoryAccessProfileCreate
            | Self::InventoryRouteCreate
            | Self::InventorySnippetCreate
            | Self::OrganizationGroupCreate
            | Self::OrganizationPolicyCreate
            | Self::OrganizationGrantCreate
            | Self::Logout => "POST",
            Self::OrganizationUpdate | Self::TeamMemberUpdate => "PATCH",
            Self::TeamInvitationRevoke
            | Self::TeamMemberRemove
            | Self::InventoryHostDelete
            | Self::InventoryHostGroupDelete
            | Self::InventoryAccessProfileDelete
            | Self::InventoryRouteDelete
            | Self::InventorySnippetDelete
            | Self::OrganizationGroupDelete
            | Self::OrganizationPolicyDelete
            | Self::OrganizationGrantDelete => "DELETE",
            Self::InventoryHostReplace
            | Self::InventoryHostGroupReplace
            | Self::InventoryAccessProfileReplace
            | Self::InventoryRouteReplace
            | Self::InventorySnippetReplace
            | Self::OrganizationGroupReplace
            | Self::OrganizationPolicyReplace
            | Self::OrganizationGrantReplace => "PUT",
        }
    }
    /// Canonical router template, never an untrusted URL.
    #[must_use]
    pub const fn route_template(self) -> &'static str {
        match self {
            Self::AccessRequestCheck => "/api/v1/orgs/{org}/access-requests/check",
            Self::AccessRequestCreate | Self::AccessRequestList => {
                "/api/v1/orgs/{org}/access-requests"
            }
            Self::AccessRequestRead => "/api/v1/orgs/{org}/access-requests/{id}",
            Self::AccessRequestDecide => "/api/v1/orgs/{org}/access-requests/{id}/decisions",
            Self::AccessRequestCancel => "/api/v1/orgs/{org}/access-requests/{id}/cancel",
            Self::AccountProfileRead => "/api/v1/accounts/me",
            Self::AuditEventList => "/api/v1/orgs/{org}/audit-events",
            Self::AuditRangeVerify => "/api/v1/orgs/{org}/audit-events/verify",
            Self::OrganizationCreate | Self::OrganizationList => "/api/v1/orgs",
            Self::OrganizationRead | Self::OrganizationUpdate => "/api/v1/orgs/{org}",
            Self::TeamInvitationCreate | Self::TeamInvitationList => {
                "/api/v1/orgs/{org}/invitations"
            }
            Self::TeamInvitationRead | Self::TeamInvitationRevoke => {
                "/api/v1/orgs/{org}/invitations/{invitation}"
            }
            Self::TeamInvitationAccept => "/api/v1/orgs/{org}/invitations/{invitation}/accept",
            Self::TeamMemberList => "/api/v1/orgs/{org}/members",
            Self::TeamMemberRead | Self::TeamMemberUpdate | Self::TeamMemberRemove => {
                "/api/v1/orgs/{org}/members/{membership}"
            }
            Self::TeamDissolve => "/api/v1/orgs/{org}/dissolve",
            Self::InventoryImportCreate => "/api/v1/orgs/{org}/inventory/imports",
            Self::InventoryHostList | Self::InventoryHostCreate => "/api/v1/orgs/{org}/hosts",
            Self::InventoryHostRead | Self::InventoryHostReplace | Self::InventoryHostDelete => {
                "/api/v1/orgs/{org}/hosts/{id}"
            }
            Self::InventoryHostGroupList | Self::InventoryHostGroupCreate => {
                "/api/v1/orgs/{org}/host-groups"
            }
            Self::InventoryHostGroupRead
            | Self::InventoryHostGroupReplace
            | Self::InventoryHostGroupDelete => "/api/v1/orgs/{org}/host-groups/{id}",
            Self::InventoryAccessProfileList | Self::InventoryAccessProfileCreate => {
                "/api/v1/orgs/{org}/access-profiles"
            }
            Self::InventoryAccessProfileRead
            | Self::InventoryAccessProfileReplace
            | Self::InventoryAccessProfileDelete => "/api/v1/orgs/{org}/access-profiles/{id}",
            Self::InventoryRouteList | Self::InventoryRouteCreate => "/api/v1/orgs/{org}/routes",
            Self::InventoryRouteRead | Self::InventoryRouteReplace | Self::InventoryRouteDelete => {
                "/api/v1/orgs/{org}/routes/{id}"
            }
            Self::InventorySnippetList | Self::InventorySnippetCreate => {
                "/api/v1/orgs/{org}/snippets"
            }
            Self::InventorySnippetRead
            | Self::InventorySnippetReplace
            | Self::InventorySnippetDelete => "/api/v1/orgs/{org}/snippets/{id}",
            Self::OrganizationGroupList | Self::OrganizationGroupCreate => {
                "/api/v1/orgs/{org}/groups"
            }
            Self::OrganizationGroupRead
            | Self::OrganizationGroupReplace
            | Self::OrganizationGroupDelete => "/api/v1/orgs/{org}/groups/{id}",
            Self::OrganizationPolicyList | Self::OrganizationPolicyCreate => {
                "/api/v1/orgs/{org}/policies"
            }
            Self::OrganizationPolicyRead
            | Self::OrganizationPolicyReplace
            | Self::OrganizationPolicyDelete => "/api/v1/orgs/{org}/policies/{id}",
            Self::OrganizationGrantList | Self::OrganizationGrantCreate => {
                "/api/v1/orgs/{org}/grants"
            }
            Self::OrganizationGrantRead
            | Self::OrganizationGrantReplace
            | Self::OrganizationGrantDelete => "/api/v1/orgs/{org}/grants/{id}",
            Self::Logout => "/api/v1/auth/accounts/browser/logout",
        }
    }
    /// Match only an exact router-owned method/template. No fallback to another profile.
    #[must_use]
    pub fn from_route(method: &str, template: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|operation| {
            operation.http_method() == method && operation.route_template() == template
        })
    }
    /// Whether this POST's exact receipt binds the real browser writer/family.
    /// Team receipts remain Account-scoped and return false.
    #[must_use]
    pub const fn uses_browser_writer_receipt(self) -> bool {
        matches!(
            self,
            Self::AccessRequestCreate
                | Self::AccessRequestDecide
                | Self::AccessRequestCancel
                | Self::InventoryImportCreate
                | Self::InventoryHostCreate
                | Self::InventoryHostGroupCreate
                | Self::InventoryAccessProfileCreate
                | Self::InventoryRouteCreate
                | Self::InventorySnippetCreate
                | Self::OrganizationGroupCreate
                | Self::OrganizationPolicyCreate
                | Self::OrganizationGrantCreate
        )
    }
}

/// Server-owned Organization writer metadata, constructed only after current authentication.
/// It grants no permission and never supplies an enrolled Device id.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccountBrowserWriter {
    account_id: Uuid,
    family_id: Uuid,
}

impl AccountBrowserWriter {
    /// Validate canonical `UUIDv7` identity shape; authentication remains the caller's duty.
    /// # Errors
    /// Rejects non-`UUIDv7` Account or family identities.
    pub fn new(account_id: Uuid, family_id: Uuid) -> Result<Self, AccountBrowserCodecError> {
        validate_uuid_v7(account_id).map_err(|_| AccountBrowserCodecError::Invalid)?;
        validate_uuid_v7(family_id).map_err(|_| AccountBrowserCodecError::Invalid)?;
        Ok(Self { account_id, family_id })
    }
    /// Distinct trusted create-receipt/audit writer kind.
    #[must_use]
    pub const fn kind(self) -> &'static str {
        "account-browser"
    }
    /// Authenticated owning Account, with no Device association.
    #[must_use]
    pub const fn account_id(self) -> Uuid {
        self.account_id
    }
    /// Family used by exact create receipts and Organization K-1 field/tombstone origins.
    #[must_use]
    pub const fn family_id(self) -> Uuid {
        self.family_id
    }
}
