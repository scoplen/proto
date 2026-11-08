// SPDX-License-Identifier: Apache-2.0
//! D-107 enrolled-device permission ceiling and registered operation requirements.

/// Exact byte-sorted scope set issued after initial first-party device authentication.
///
/// Refresh may preserve or narrow its family's original ceiling, never expand it. These
/// coarse permissions do not replace identity, `DPoP`, replay, membership, or policy checks.
pub const INITIAL_DEVICE_ACCESS_SCOPE: &str = "account:read ca:read ca:write certificates:issue inventory:read inventory:write keys:read keys:write orgs:create orgs:read orgs:write policies:read policies:write sync:read sync:write teams:join teams:manage";

/// Known initial enrolled-device scopes. Unknown valid JWT scope tokens remain parseable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceAccessScope {
    /// Read the current device's account profile and signed device statements.
    AccountRead,
    /// Read current Organization user-CA public trust.
    CaRead,
    /// Provision an Organization local user CA under current policy.
    CaWrite,
    /// Issue a source-bound certificate after per-target authorization.
    CertificatesIssue,
    /// Read individually authorized Organization inventory.
    InventoryRead,
    /// Author Organization inventory under current policy.
    InventoryWrite,
    /// Read that account's encrypted K-4 key bundle.
    KeysRead,
    /// Update that account's encrypted K-4 key bundle with the required signatures and wraps.
    KeysWrite,
    /// Create a team under the deployment's current creation policy.
    OrganizationCreate,
    /// Discover the current Account's own active team memberships.
    OrganizationRead,
    /// Update Organization settings under current membership and policy authorization.
    OrganizationWrite,
    /// Read current Organization groups and policies.
    PoliciesRead,
    /// Author Organization policies under current policy.
    PoliciesWrite,
    /// Read authorized vault data and establish authorized notification subscriptions.
    SyncRead,
    /// Mutate authorized vault state, subject to each operation's additional checks.
    SyncWrite,
    /// Preview and accept a designated invitation, or leave the caller's own team membership.
    TeamsJoin,
    /// Manage invitations, members and Owner-authorized team dissolution.
    TeamsManage,
}

impl DeviceAccessScope {
    /// Every initial scope in canonical byte order.
    pub const ALL: [Self; 17] = [
        Self::AccountRead,
        Self::CaRead,
        Self::CaWrite,
        Self::CertificatesIssue,
        Self::InventoryRead,
        Self::InventoryWrite,
        Self::KeysRead,
        Self::KeysWrite,
        Self::OrganizationCreate,
        Self::OrganizationRead,
        Self::OrganizationWrite,
        Self::PoliciesRead,
        Self::PoliciesWrite,
        Self::SyncRead,
        Self::SyncWrite,
        Self::TeamsJoin,
        Self::TeamsManage,
    ];

    /// Exact case-sensitive ASCII scope token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AccountRead => "account:read",
            Self::CaRead => "ca:read",
            Self::CaWrite => "ca:write",
            Self::CertificatesIssue => "certificates:issue",
            Self::InventoryRead => "inventory:read",
            Self::InventoryWrite => "inventory:write",
            Self::KeysRead => "keys:read",
            Self::KeysWrite => "keys:write",
            Self::OrganizationCreate => "orgs:create",
            Self::OrganizationRead => "orgs:read",
            Self::OrganizationWrite => "orgs:write",
            Self::PoliciesRead => "policies:read",
            Self::PoliciesWrite => "policies:write",
            Self::SyncRead => "sync:read",
            Self::SyncWrite => "sync:write",
            Self::TeamsJoin => "teams:join",
            Self::TeamsManage => "teams:manage",
        }
    }

    /// Recognize a known token without changing JWT lexical acceptance of unknown tokens.
    #[must_use]
    pub fn from_token(token: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|scope| scope.as_str() == token)
    }

    /// Test exact membership in an already verified canonical D-100 scope claim.
    ///
    /// This does not authenticate a token or authorize an operation. Callers first perform
    /// signature, `DPoP`, replay, and current-principal checks, then check the operation's scope
    /// before accessing its protected resource. There are no wildcards or implied read rights.
    #[must_use]
    pub fn is_present_in(self, verified_scope: &str) -> bool {
        verified_scope.split(' ').any(|token| token == self.as_str())
    }
}

/// A protected operation registered for the initial enrolled-device profile.
///
/// Register an operation explicitly with its router. Unknown protected routes have no mapping
/// and must fail closed for this profile. A scope match is necessary, not authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceAccessOperation {
    /// Read the current account profile.
    AccountProfileRead,
    /// Read the complete current-account signed device-statement snapshot.
    AccountDevicesRead,
    /// Create an Organization with the current Account as its initial owner.
    OrganizationCreate,
    /// List the current Account's own active Organization memberships.
    OrganizationList,
    /// Read the current Account's own Organization membership projection.
    OrganizationRead,
    /// Update only an Organization's name under the current projection's precondition.
    OrganizationUpdate,
    /// Create an invitation bound to one existing Account.
    TeamInvitationCreate,
    /// List a team's invitations under current administrative authority.
    TeamInvitationList,
    /// Read an invitation as an authorized administrator or its fixed recipient.
    TeamInvitationRead,
    /// Accept an invitation as its fixed recipient.
    TeamInvitationAccept,
    /// Revoke a pending or locked invitation.
    TeamInvitationRevoke,
    /// List team memberships under current administrative authority.
    TeamMemberList,
    /// Read one membership under current administrative authority.
    TeamMemberRead,
    /// Update membership roles and active/suspended status.
    TeamMemberUpdate,
    /// Remove a membership administratively or leave the caller's own membership.
    TeamMemberRemove,
    /// Dissolve a team as a current Owner.
    TeamDissolve,
    /// Host List in the current Organization.
    InventoryHostList,
    /// Host Read in the current Organization.
    InventoryHostRead,
    /// Host Create in the current Organization.
    InventoryHostCreate,
    /// Host Replace in the current Organization.
    InventoryHostReplace,
    /// Host Delete in the current Organization.
    InventoryHostDelete,
    /// Access Profile List in the current Organization.
    InventoryAccessProfileList,
    /// Access Profile Read in the current Organization.
    InventoryAccessProfileRead,
    /// Access Profile Create in the current Organization.
    InventoryAccessProfileCreate,
    /// Access Profile Replace in the current Organization.
    InventoryAccessProfileReplace,
    /// Access Profile Delete in the current Organization.
    InventoryAccessProfileDelete,
    /// Route List in the current Organization.
    InventoryRouteList,
    /// Route Read in the current Organization.
    InventoryRouteRead,
    /// Route Create in the current Organization.
    InventoryRouteCreate,
    /// Route Replace in the current Organization.
    InventoryRouteReplace,
    /// Route Delete in the current Organization.
    InventoryRouteDelete,
    /// Host Group List in the current Organization.
    InventoryHostGroupList,
    /// Host Group Read in the current Organization.
    InventoryHostGroupRead,
    /// Host Group Create in the current Organization.
    InventoryHostGroupCreate,
    /// Host Group Replace in the current Organization.
    InventoryHostGroupReplace,
    /// Host Group Delete in the current Organization.
    InventoryHostGroupDelete,
    /// Trust Record List in the current Organization.
    InventoryTrustRecordList,
    /// Trust Record Read in the current Organization.
    InventoryTrustRecordRead,
    /// Trust Record Create in the current Organization.
    InventoryTrustRecordCreate,
    /// Trust Record Replace in the current Organization.
    InventoryTrustRecordReplace,
    /// Trust Record Delete in the current Organization.
    InventoryTrustRecordDelete,
    /// Snippet List in the current Organization.
    InventorySnippetList,
    /// Snippet Read in the current Organization.
    InventorySnippetRead,
    /// Snippet Create in the current Organization.
    InventorySnippetCreate,
    /// Snippet Replace in the current Organization.
    InventorySnippetReplace,
    /// Snippet Delete in the current Organization.
    InventorySnippetDelete,
    /// Gateway Network List in the current Organization.
    InventoryGatewayNetworkList,
    /// Gateway Network Read in the current Organization.
    InventoryGatewayNetworkRead,
    /// Gateway Network Create in the current Organization.
    InventoryGatewayNetworkCreate,
    /// Gateway Network Replace in the current Organization.
    InventoryGatewayNetworkReplace,
    /// Gateway Network Delete in the current Organization.
    InventoryGatewayNetworkDelete,
    /// Create one local Group with current same-team Membership associations.
    OrganizationGroupCreate,
    /// List Groups under current administrative read authority.
    OrganizationGroupList,
    /// Read one Group under current administrative read authority.
    OrganizationGroupRead,
    /// Completely replace one local Group's name and Membership associations.
    OrganizationGroupReplace,
    /// Delete one local Group after checking current policy dependencies.
    OrganizationGroupDelete,
    /// Create one current Organization's persisted custom policy.
    OrganizationPolicyCreate,
    /// List the current Organization's custom policies.
    OrganizationPolicyList,
    /// Read one current Organization's custom policy.
    OrganizationPolicyRead,
    /// Completely replace one current Organization's custom policy.
    OrganizationPolicyReplace,
    /// Delete one current Organization's custom policy.
    OrganizationPolicyDelete,
    /// List public user-CA metadata under current Organization membership.
    UserCaList,
    /// Read one current Organization's public user CA.
    UserCaRead,
    /// Read the current Organization user CA's complete revocation snapshot.
    UserCaKrlRead,
    /// Provision the initial local user CA under current policy authority.
    UserCaCreate,
    /// Issue a scoped user certificate under current target authority.
    UserCertificateIssue,
    /// Read account keys.
    AccountKeysRead,
    /// Update account keys.
    AccountKeysWrite,
    /// Start a sync session and discover authorized vaults.
    SyncSession,
    /// Read a vault's encrypted key records.
    VaultKeysRead,
    /// Read vault changes.
    VaultChangesRead,
    /// Read a vault snapshot.
    VaultSnapshotRead,
    /// Read a complete revision-bound Organization view.
    OrganizationViewRead,
    /// Read an object's retained versions.
    ObjectVersionsRead,
    /// Authenticate notifications and recheck authorized subscriptions and delivery.
    Notifications,
    /// Create a shared vault.
    VaultCreate,
    /// Write a vault's object batch.
    VaultObjectsWrite,
    /// Advance the device's acknowledged vault cursor.
    VaultAcknowledge,
    /// Publish a vault key epoch.
    VaultEpochPublish,
    /// Add a vault member.
    VaultMemberAdd,
    /// Retire a vault key epoch.
    VaultEpochRetire,
    /// Remove a vault member.
    VaultMemberRemove,
}

impl DeviceAccessOperation {
    /// Every operation in the D-107 registry.
    pub const ALL: [Self; 82] = [
        Self::AccountProfileRead,
        Self::AccountDevicesRead,
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
        Self::InventoryHostRead,
        Self::InventoryHostCreate,
        Self::InventoryHostReplace,
        Self::InventoryHostDelete,
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
        Self::InventoryHostGroupList,
        Self::InventoryHostGroupRead,
        Self::InventoryHostGroupCreate,
        Self::InventoryHostGroupReplace,
        Self::InventoryHostGroupDelete,
        Self::InventoryTrustRecordList,
        Self::InventoryTrustRecordRead,
        Self::InventoryTrustRecordCreate,
        Self::InventoryTrustRecordReplace,
        Self::InventoryTrustRecordDelete,
        Self::InventorySnippetList,
        Self::InventorySnippetRead,
        Self::InventorySnippetCreate,
        Self::InventorySnippetReplace,
        Self::InventorySnippetDelete,
        Self::InventoryGatewayNetworkList,
        Self::InventoryGatewayNetworkRead,
        Self::InventoryGatewayNetworkCreate,
        Self::InventoryGatewayNetworkReplace,
        Self::InventoryGatewayNetworkDelete,
        Self::OrganizationGroupCreate,
        Self::OrganizationGroupList,
        Self::OrganizationGroupRead,
        Self::OrganizationGroupReplace,
        Self::OrganizationGroupDelete,
        Self::OrganizationPolicyCreate,
        Self::OrganizationPolicyList,
        Self::OrganizationPolicyRead,
        Self::OrganizationPolicyReplace,
        Self::OrganizationPolicyDelete,
        Self::UserCaList,
        Self::UserCaRead,
        Self::UserCaKrlRead,
        Self::UserCaCreate,
        Self::UserCertificateIssue,
        Self::AccountKeysRead,
        Self::AccountKeysWrite,
        Self::SyncSession,
        Self::VaultKeysRead,
        Self::VaultChangesRead,
        Self::VaultSnapshotRead,
        Self::OrganizationViewRead,
        Self::ObjectVersionsRead,
        Self::Notifications,
        Self::VaultCreate,
        Self::VaultObjectsWrite,
        Self::VaultAcknowledge,
        Self::VaultEpochPublish,
        Self::VaultMemberAdd,
        Self::VaultEpochRetire,
        Self::VaultMemberRemove,
    ];

    /// Exact alternative coarse scopes; one must be present before current authorization.
    ///
    /// The matching scope does not select a role or establish authority. For example, the
    /// `teams:join` read path still requires the invitation's fixed recipient Account.
    #[must_use]
    pub const fn accepted_scopes(self) -> &'static [DeviceAccessScope] {
        match self {
            Self::AccountProfileRead | Self::AccountDevicesRead => {
                &[DeviceAccessScope::AccountRead]
            }
            Self::OrganizationCreate => &[DeviceAccessScope::OrganizationCreate],
            Self::OrganizationList | Self::OrganizationRead => {
                &[DeviceAccessScope::OrganizationRead]
            }
            Self::OrganizationUpdate => &[DeviceAccessScope::OrganizationWrite],
            Self::TeamInvitationRead | Self::TeamMemberRemove => {
                &[DeviceAccessScope::TeamsJoin, DeviceAccessScope::TeamsManage]
            }
            Self::TeamInvitationAccept => &[DeviceAccessScope::TeamsJoin],
            Self::TeamInvitationCreate
            | Self::TeamInvitationList
            | Self::TeamInvitationRevoke
            | Self::TeamMemberList
            | Self::TeamMemberRead
            | Self::TeamMemberUpdate
            | Self::TeamDissolve
            | Self::OrganizationGroupCreate
            | Self::OrganizationGroupReplace
            | Self::OrganizationGroupDelete => &[DeviceAccessScope::TeamsManage],
            Self::OrganizationGroupList
            | Self::OrganizationGroupRead
            | Self::OrganizationPolicyList
            | Self::OrganizationPolicyRead => &[DeviceAccessScope::PoliciesRead],
            Self::OrganizationPolicyCreate
            | Self::OrganizationPolicyReplace
            | Self::OrganizationPolicyDelete => &[DeviceAccessScope::PoliciesWrite],
            Self::InventoryHostList
            | Self::InventoryHostRead
            | Self::InventoryAccessProfileList
            | Self::InventoryAccessProfileRead
            | Self::InventoryRouteList
            | Self::InventoryRouteRead
            | Self::InventoryHostGroupList
            | Self::InventoryHostGroupRead
            | Self::InventoryTrustRecordList
            | Self::InventoryTrustRecordRead
            | Self::InventorySnippetList
            | Self::InventorySnippetRead
            | Self::InventoryGatewayNetworkList
            | Self::InventoryGatewayNetworkRead => &[DeviceAccessScope::InventoryRead],
            Self::InventoryHostCreate
            | Self::InventoryHostReplace
            | Self::InventoryHostDelete
            | Self::InventoryAccessProfileCreate
            | Self::InventoryAccessProfileReplace
            | Self::InventoryAccessProfileDelete
            | Self::InventoryRouteCreate
            | Self::InventoryRouteReplace
            | Self::InventoryRouteDelete
            | Self::InventoryHostGroupCreate
            | Self::InventoryHostGroupReplace
            | Self::InventoryHostGroupDelete
            | Self::InventoryTrustRecordCreate
            | Self::InventoryTrustRecordReplace
            | Self::InventoryTrustRecordDelete
            | Self::InventorySnippetCreate
            | Self::InventorySnippetReplace
            | Self::InventorySnippetDelete
            | Self::InventoryGatewayNetworkCreate
            | Self::InventoryGatewayNetworkReplace
            | Self::InventoryGatewayNetworkDelete => &[DeviceAccessScope::InventoryWrite],
            Self::UserCaList | Self::UserCaRead | Self::UserCaKrlRead => {
                &[DeviceAccessScope::CaRead]
            }
            Self::UserCaCreate => &[DeviceAccessScope::CaWrite],
            Self::UserCertificateIssue => &[DeviceAccessScope::CertificatesIssue],
            Self::AccountKeysRead => &[DeviceAccessScope::KeysRead],
            Self::AccountKeysWrite => &[DeviceAccessScope::KeysWrite],
            Self::SyncSession
            | Self::VaultKeysRead
            | Self::VaultChangesRead
            | Self::VaultSnapshotRead
            | Self::OrganizationViewRead
            | Self::ObjectVersionsRead
            | Self::Notifications => &[DeviceAccessScope::SyncRead],
            Self::VaultCreate
            | Self::VaultObjectsWrite
            | Self::VaultAcknowledge
            | Self::VaultEpochPublish
            | Self::VaultMemberAdd
            | Self::VaultEpochRetire
            | Self::VaultMemberRemove => &[DeviceAccessScope::SyncWrite],
        }
    }

    /// Check this operation's any-of scope ceiling in an already verified scope claim.
    #[must_use]
    pub fn has_accepted_scope(self, verified_scope: &str) -> bool {
        self.accepted_scopes().iter().any(|scope| scope.is_present_in(verified_scope))
    }

    /// The router's canonical method for this operation.
    /// Notifications return the classic handshake's `GET`; [`Self::from_route`] also recognizes
    /// the defined HTTP/2 `CONNECT`. Bind `DPoP` to the actual opening method in either case.
    #[must_use]
    pub const fn http_method(self) -> &'static str {
        match self {
            Self::AccountProfileRead
            | Self::AccountDevicesRead
            | Self::OrganizationList
            | Self::OrganizationRead
            | Self::TeamInvitationList
            | Self::TeamInvitationRead
            | Self::TeamMemberList
            | Self::TeamMemberRead
            | Self::AccountKeysRead
            | Self::VaultKeysRead
            | Self::VaultChangesRead
            | Self::VaultSnapshotRead
            | Self::OrganizationViewRead
            | Self::ObjectVersionsRead
            | Self::InventoryHostList
            | Self::InventoryHostRead
            | Self::InventoryAccessProfileList
            | Self::InventoryAccessProfileRead
            | Self::InventoryRouteList
            | Self::InventoryRouteRead
            | Self::InventoryHostGroupList
            | Self::InventoryHostGroupRead
            | Self::InventoryTrustRecordList
            | Self::InventoryTrustRecordRead
            | Self::InventorySnippetList
            | Self::InventorySnippetRead
            | Self::InventoryGatewayNetworkList
            | Self::InventoryGatewayNetworkRead
            | Self::OrganizationGroupList
            | Self::OrganizationGroupRead
            | Self::OrganizationPolicyList
            | Self::OrganizationPolicyRead
            | Self::UserCaList
            | Self::UserCaRead
            | Self::UserCaKrlRead
            | Self::Notifications => "GET",
            Self::AccountKeysWrite
            | Self::OrganizationGroupReplace
            | Self::OrganizationPolicyReplace
            | Self::InventoryHostReplace
            | Self::InventoryAccessProfileReplace
            | Self::InventoryRouteReplace
            | Self::InventoryHostGroupReplace
            | Self::InventoryTrustRecordReplace
            | Self::InventorySnippetReplace
            | Self::InventoryGatewayNetworkReplace => "PUT",
            Self::OrganizationUpdate | Self::TeamMemberUpdate => "PATCH",
            Self::VaultMemberRemove
            | Self::TeamInvitationRevoke
            | Self::TeamMemberRemove
            | Self::OrganizationGroupDelete
            | Self::OrganizationPolicyDelete
            | Self::InventoryHostDelete
            | Self::InventoryAccessProfileDelete
            | Self::InventoryRouteDelete
            | Self::InventoryHostGroupDelete
            | Self::InventoryTrustRecordDelete
            | Self::InventorySnippetDelete
            | Self::InventoryGatewayNetworkDelete => "DELETE",
            Self::SyncSession
            | Self::OrganizationCreate
            | Self::TeamInvitationCreate
            | Self::TeamInvitationAccept
            | Self::TeamDissolve
            | Self::UserCaCreate
            | Self::UserCertificateIssue
            | Self::OrganizationGroupCreate
            | Self::OrganizationPolicyCreate
            | Self::InventoryHostCreate
            | Self::InventoryAccessProfileCreate
            | Self::InventoryRouteCreate
            | Self::InventoryHostGroupCreate
            | Self::InventoryTrustRecordCreate
            | Self::InventorySnippetCreate
            | Self::InventoryGatewayNetworkCreate
            | Self::VaultCreate
            | Self::VaultObjectsWrite
            | Self::VaultAcknowledge
            | Self::VaultEpochPublish
            | Self::VaultMemberAdd
            | Self::VaultEpochRetire => "POST",
        }
    }

    /// Full canonical route template, using the placeholder names specified in D-107.
    #[must_use]
    pub const fn route_template(self) -> &'static str {
        match self {
            Self::AccountProfileRead => "/api/v1/accounts/me",
            Self::AccountDevicesRead => "/api/v1/accounts/me/devices",
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
            Self::InventoryHostList | Self::InventoryHostCreate => "/api/v1/orgs/{org}/hosts",
            Self::InventoryHostRead | Self::InventoryHostReplace | Self::InventoryHostDelete => {
                "/api/v1/orgs/{org}/hosts/{id}"
            }
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
            Self::InventoryHostGroupList | Self::InventoryHostGroupCreate => {
                "/api/v1/orgs/{org}/host-groups"
            }
            Self::InventoryHostGroupRead
            | Self::InventoryHostGroupReplace
            | Self::InventoryHostGroupDelete => "/api/v1/orgs/{org}/host-groups/{id}",
            Self::InventoryTrustRecordList | Self::InventoryTrustRecordCreate => {
                "/api/v1/orgs/{org}/trust-records"
            }
            Self::InventoryTrustRecordRead
            | Self::InventoryTrustRecordReplace
            | Self::InventoryTrustRecordDelete => "/api/v1/orgs/{org}/trust-records/{id}",
            Self::InventorySnippetList | Self::InventorySnippetCreate => {
                "/api/v1/orgs/{org}/snippets"
            }
            Self::InventorySnippetRead
            | Self::InventorySnippetReplace
            | Self::InventorySnippetDelete => "/api/v1/orgs/{org}/snippets/{id}",
            Self::InventoryGatewayNetworkList | Self::InventoryGatewayNetworkCreate => {
                "/api/v1/orgs/{org}/gateway-networks"
            }
            Self::InventoryGatewayNetworkRead
            | Self::InventoryGatewayNetworkReplace
            | Self::InventoryGatewayNetworkDelete => "/api/v1/orgs/{org}/gateway-networks/{id}",
            Self::OrganizationGroupCreate | Self::OrganizationGroupList => {
                "/api/v1/orgs/{org}/groups"
            }
            Self::OrganizationGroupRead
            | Self::OrganizationGroupReplace
            | Self::OrganizationGroupDelete => "/api/v1/orgs/{org}/groups/{id}",
            Self::OrganizationPolicyCreate | Self::OrganizationPolicyList => {
                "/api/v1/orgs/{org}/policies"
            }
            Self::OrganizationPolicyRead
            | Self::OrganizationPolicyReplace
            | Self::OrganizationPolicyDelete => "/api/v1/orgs/{org}/policies/{id}",
            Self::UserCaList | Self::UserCaCreate => "/api/v1/orgs/{org}/certificate-authorities",
            Self::UserCaRead => "/api/v1/orgs/{org}/certificate-authorities/{id}",
            Self::UserCaKrlRead => "/api/v1/orgs/{org}/certificate-authorities/{id}/krl",
            Self::UserCertificateIssue => "/api/v1/orgs/{org}/certificates",
            Self::AccountKeysRead | Self::AccountKeysWrite => "/sync/v1/keys",
            Self::SyncSession => "/sync/v1/session",
            Self::VaultKeysRead => "/sync/v1/vaults/{vault}/keys",
            Self::VaultChangesRead => "/sync/v1/vaults/{vault}/changes",
            Self::VaultSnapshotRead => "/sync/v1/vaults/{vault}/snapshot",
            Self::OrganizationViewRead => "/sync/v1/vaults/{vault}/view",
            Self::ObjectVersionsRead => "/sync/v1/vaults/{vault}/objects/{object}/versions",
            Self::Notifications => "/sync/v1/notify",
            Self::VaultCreate => "/sync/v1/vaults",
            Self::VaultObjectsWrite => "/sync/v1/vaults/{vault}/objects",
            Self::VaultAcknowledge => "/sync/v1/vaults/{vault}/ack",
            Self::VaultEpochPublish => "/sync/v1/vaults/{vault}/epochs",
            Self::VaultMemberAdd => "/sync/v1/vaults/{vault}/members",
            Self::VaultEpochRetire => "/sync/v1/vaults/{vault}/epochs/{epoch}/retire",
            Self::VaultMemberRemove => "/sync/v1/vaults/{vault}/members/{account}",
        }
    }

    /// Look up an exact router-owned method and canonical route template.
    ///
    /// Never pass an untrusted path as a template or normalize an alias into this table.
    /// A missing mapping cannot authorize a protected route with this device profile.
    /// Notifications accept both the classic `GET` and HTTP/2 extended `CONNECT` handshakes.
    #[must_use]
    pub fn from_route(method: &str, route_template: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|operation| {
            operation.route_template() == route_template
                && (operation.http_method() == method
                    || (*operation == Self::Notifications && method == "CONNECT"))
        })
    }
}
