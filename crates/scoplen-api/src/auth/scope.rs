// SPDX-License-Identifier: Apache-2.0
//! D-107 enrolled-device permission ceiling and registered operation requirements.

/// Exact byte-sorted scope set issued after initial first-party device authentication.
///
/// Refresh may preserve or narrow its family's original ceiling, never expand it. These
/// coarse permissions do not replace identity, `DPoP`, replay, membership, or policy checks.
pub const INITIAL_DEVICE_ACCESS_SCOPE: &str =
    "account:read keys:read keys:write sync:read sync:write";

/// Known initial enrolled-device scopes. Unknown valid JWT scope tokens remain parseable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceAccessScope {
    /// Read the current device's account profile and signed device statements.
    AccountRead,
    /// Read that account's encrypted K-4 key bundle.
    KeysRead,
    /// Update that account's encrypted K-4 key bundle with the required signatures and wraps.
    KeysWrite,
    /// Read authorized vault data and establish authorized notification subscriptions.
    SyncRead,
    /// Mutate authorized vault state, subject to each operation's additional checks.
    SyncWrite,
}

impl DeviceAccessScope {
    /// Every initial scope in canonical byte order.
    pub const ALL: [Self; 5] =
        [Self::AccountRead, Self::KeysRead, Self::KeysWrite, Self::SyncRead, Self::SyncWrite];

    /// Exact case-sensitive ASCII scope token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AccountRead => "account:read",
            Self::KeysRead => "keys:read",
            Self::KeysWrite => "keys:write",
            Self::SyncRead => "sync:read",
            Self::SyncWrite => "sync:write",
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
    pub const ALL: [Self; 17] = [
        Self::AccountProfileRead,
        Self::AccountDevicesRead,
        Self::AccountKeysRead,
        Self::AccountKeysWrite,
        Self::SyncSession,
        Self::VaultKeysRead,
        Self::VaultChangesRead,
        Self::VaultSnapshotRead,
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

    /// Exact coarse scope required in addition to the operation's other authorization checks.
    #[must_use]
    pub const fn required_scope(self) -> DeviceAccessScope {
        match self {
            Self::AccountProfileRead | Self::AccountDevicesRead => DeviceAccessScope::AccountRead,
            Self::AccountKeysRead => DeviceAccessScope::KeysRead,
            Self::AccountKeysWrite => DeviceAccessScope::KeysWrite,
            Self::SyncSession
            | Self::VaultKeysRead
            | Self::VaultChangesRead
            | Self::VaultSnapshotRead
            | Self::ObjectVersionsRead
            | Self::Notifications => DeviceAccessScope::SyncRead,
            Self::VaultCreate
            | Self::VaultObjectsWrite
            | Self::VaultAcknowledge
            | Self::VaultEpochPublish
            | Self::VaultMemberAdd
            | Self::VaultEpochRetire
            | Self::VaultMemberRemove => DeviceAccessScope::SyncWrite,
        }
    }

    /// The router's canonical method for this operation.
    #[must_use]
    pub const fn http_method(self) -> &'static str {
        match self {
            Self::AccountProfileRead
            | Self::AccountDevicesRead
            | Self::AccountKeysRead
            | Self::VaultKeysRead
            | Self::VaultChangesRead
            | Self::VaultSnapshotRead
            | Self::ObjectVersionsRead
            | Self::Notifications => "GET",
            Self::AccountKeysWrite => "PUT",
            Self::VaultMemberRemove => "DELETE",
            Self::SyncSession
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
            Self::AccountKeysRead | Self::AccountKeysWrite => "/sync/v1/keys",
            Self::SyncSession => "/sync/v1/session",
            Self::VaultKeysRead => "/sync/v1/vaults/{vault}/keys",
            Self::VaultChangesRead => "/sync/v1/vaults/{vault}/changes",
            Self::VaultSnapshotRead => "/sync/v1/vaults/{vault}/snapshot",
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
    #[must_use]
    pub fn from_route(method: &str, route_template: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|operation| {
            operation.http_method() == method && operation.route_template() == route_template
        })
    }
}
