// SPDX-License-Identifier: Apache-2.0
//! Independent deployment Operator permissions and D-124 intrinsic session termination.

/// Exact initial Operator scope. It grants no Account, Device or organization authority.
pub const INITIAL_OPERATOR_ACCESS_SCOPE: &str = "personal-invitation:issue";

/// The initial deployment Operator's registered coarse permission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperatorAccessScope {
    /// Issue a one-use Personal account invitation, subject to current Operator and Cedar checks.
    PersonalInvitationIssue,
}

impl OperatorAccessScope {
    /// Every registered Operator scope, in canonical byte order.
    pub const ALL: [Self; 1] = [Self::PersonalInvitationIssue];

    /// Exact case-sensitive scope token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PersonalInvitationIssue => INITIAL_OPERATOR_ACCESS_SCOPE,
        }
    }

    /// Recognize a registered token without accepting aliases or wildcard permissions.
    #[must_use]
    pub fn from_token(token: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|scope| scope.as_str() == token)
    }

    /// Check exact membership in an already authenticated scope claim.
    #[must_use]
    pub fn is_present_in(self, verified_scope: &str) -> bool {
        verified_scope.split(' ').any(|token| token == self.as_str())
    }
}

/// Authenticated requirements are explicit; an intrinsic operation never means anonymous access.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperatorAccessRequirement {
    /// A business permission in addition to current Operator authentication and authorization.
    Scope(OperatorAccessScope),
    /// End only the verified caller's current family, subject to D-124's current-state checks.
    SelfSessionTermination,
}

/// Router-owned registry for the independent Operator profile; unmapped routes fail closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperatorAccessOperation {
    /// Issue a Personal enrollment invitation.
    PersonalInvitationIssue,
    /// Terminate only the caller's token-bound current Operator browser family.
    Logout,
}

impl OperatorAccessOperation {
    /// All registered Operator operations.
    pub const ALL: [Self; 2] = [Self::PersonalInvitationIssue, Self::Logout];

    /// Exact authenticated requirement; neither branch supplies authentication by itself.
    #[must_use]
    pub const fn requirement(self) -> OperatorAccessRequirement {
        match self {
            Self::PersonalInvitationIssue => {
                OperatorAccessRequirement::Scope(OperatorAccessScope::PersonalInvitationIssue)
            }
            Self::Logout => OperatorAccessRequirement::SelfSessionTermination,
        }
    }

    /// Canonical HTTP method.
    #[must_use]
    pub const fn http_method(self) -> &'static str {
        "POST"
    }

    /// Canonical router template, never an untrusted URL.
    #[must_use]
    pub const fn route_template(self) -> &'static str {
        match self {
            Self::PersonalInvitationIssue => "/api/v1/admin/personal-invitations",
            Self::Logout => "/api/v1/auth/operator/logout",
        }
    }

    /// Match only an exact router-owned method and route.
    #[must_use]
    pub fn from_route(method: &str, template: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|operation| {
            operation.http_method() == method && operation.route_template() == template
        })
    }
}
