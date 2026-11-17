// SPDX-License-Identifier: Apache-2.0
//! Named-member Host grants and their exclusive certificate cutoff (D-147).

use std::collections::HashMap;

use cedar_policy::{
    Decision, Entities, PolicyId, PolicySet, Request, SlotId, Template, ValidationMode, Validator,
};
use scoplen_model::validate_uuid_v7;
use serde_json::json;
use uuid::Uuid;

use super::{
    OrganizationAuthorizationContext, OrganizationAuthorizationError as Error,
    OrganizationAuthorizer, uid,
};
use crate::grant::GrantFields;

/// A retained Grant with its trusted durable owner, loaded in the current snapshot.
///
/// The consumer supplies only current, unwithdrawn rows. This value cannot establish
/// database ownership, current Membership/Host state or authentication by itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrganizationHostGrant {
    /// Stable Grant Resource identifier.
    pub id: Uuid,
    /// Immutable owner read from trusted storage, never from request fields.
    pub organization: Uuid,
    /// The complete validated Grant fields.
    pub fields: GrantFields,
}

impl OrganizationHostGrant {
    /// Generate the canonical template and its Account/Host-linked permit.
    ///
    /// `account` must be resolved from this Grant's current Membership by the trusted
    /// consumer. The policy establishes no visibility or current-state authority.
    ///
    /// # Errors
    /// Rejects invalid identifiers, Grant fields or canonical schema validation.
    pub fn policy_set(&self, account: Uuid) -> Result<PolicySet, Error> {
        self.policy_set_with_ids(account, self.template_id(), self.policy_id())
    }

    fn policy_set_with_ids(
        &self,
        account: Uuid,
        template_id: PolicyId,
        policy_id: PolicyId,
    ) -> Result<PolicySet, Error> {
        self.validate()?;
        validate_uuid_v7(account).map_err(|_| Error::InvalidContext)?;
        let context = |name| json!({".": {"left": {"Var": "context"}, "attr": name}});
        let mut conditions = vec![
            json!({"==": {"left": context("organization"), "right": {
                "Value": {"__entity": {"type": "Organization", "id": self.organization.to_string()}}
            }}}),
            json!({"==": {"left": context("membership"), "right": {
                "Value": {"__entity": {"type": "Membership", "id": self.fields.membership.to_string()}}
            }}}),
            json!({"==": {"left": context("remote_user"), "right": {"Value": self.fields.remote_user}}}),
            json!({">=": {"left": context("now"), "right": {"Value": self.fields.valid_from}}}),
        ];
        if let Some(until) = self.fields.valid_until {
            conditions.push(json!({"<": {"left": context("now"), "right": {"Value": until}}}));
        }
        let body = conditions.into_iter().fold(
            json!({"Value": true}),
            |left, right| json!({"&&": {"left": left, "right": right}}),
        );
        let template = Template::from_json(
            Some(template_id.clone()),
            json!({
                "effect": "permit",
                "principal": {"op": "==", "slot": "?principal"},
                "action": {"op": "==", "entity": {"type": "Action", "id": "connect"}},
                "resource": {"op": "==", "slot": "?resource"},
                "conditions": [{"kind": "when", "body": body}]
            }),
        )
        .map_err(|_| Error::InvalidConfiguration)?;
        let mut policies = PolicySet::new();
        policies.add_template(template).map_err(|_| Error::InvalidConfiguration)?;
        policies
            .link(
                template_id,
                policy_id,
                HashMap::from([
                    (SlotId::principal(), uid("Account", account)?),
                    (SlotId::resource(), uid("Host", self.fields.host)?),
                ]),
            )
            .map_err(|_| Error::InvalidConfiguration)?;
        let schema = super::super::CEDAR_SCHEMA.parse().map_err(|_| Error::InvalidConfiguration)?;
        if !Validator::new(schema).validate(&policies, ValidationMode::Strict).validation_passed() {
            return Err(Error::InvalidConfiguration);
        }
        Ok(policies)
    }

    fn validate(&self) -> Result<(), Error> {
        for id in [self.id, self.organization] {
            validate_uuid_v7(id).map_err(|_| Error::InvalidConfiguration)?;
        }
        self.fields.validate().map_err(|_| Error::InvalidConfiguration)
    }

    fn policy_id(&self) -> PolicyId {
        PolicyId::new(format!("grant-{}", self.id))
    }

    fn template_id(&self) -> PolicyId {
        PolicyId::new(format!("grant-template-{}", self.id))
    }
}

fn unused_id(policies: &PolicySet, base: &PolicyId) -> PolicyId {
    let mut id = base.clone();
    let mut suffix = 0_usize;
    while policies.policy(&id).is_some()
        || policies.template(&id).is_some()
        || policies.policies().any(|policy| policy.id() == &id)
        || policies.templates().any(|template| template.id() == &id)
    {
        suffix += 1;
        id = PolicyId::new(format!("{base}-{suffix}"));
    }
    id
}

/// Connect decision with the exclusive Grant bound, if Grant authority is needed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectAuthorization {
    /// No current permit, or an applicable explicit forbid.
    Deny,
    /// Current connect authority; other existing certificate lifetime bounds still apply.
    Allow {
        /// Exclusive whole Unix second; `None` means no Grant-specific expiry cap.
        not_after: Option<u64>,
    },
}

impl OrganizationAuthorizer {
    /// Evaluate one explicit Host connect using current ordinary policies and Grants.
    ///
    /// Only explicit `hosts` certificate requests may use Host Grants. For `host_groups`,
    /// consumers keep the ordinary [`Self::authorize`] path and must not load/pass Grants.
    /// Each target still needs independent visibility. For multiple explicit Hosts, require
    /// every decision and use the earliest finite cutoff along with the ordinary TTL limits.
    /// Recheck current authority on exact original certificate receipt confirmation.
    ///
    /// An independent ordinary permit removes the Grant-specific cap. Applicable Grants
    /// are alternatives, so their latest expiry wins; any nonexpiring match removes it.
    /// All existing guards, explicit forbids and evaluation errors remain authoritative.
    /// This evaluates current truth only, not future truth of arbitrary policy conditions.
    ///
    /// # Errors
    /// Rejects non-Host/non-connect requests, invalid Grant storage data, foreign owners,
    /// invalid graphs/bindings and every Cedar evaluation error.
    pub fn authorize_connect(
        &self,
        trusted: &OrganizationAuthorizationContext,
        request: &Request,
        entities: &Entities,
        grants: &[OrganizationHostGrant],
    ) -> Result<ConnectAuthorization, Error> {
        if request.action().map(|action| action.id().unescaped()) != Some("connect")
            || request.resource().is_none_or(|resource| resource.type_name().to_string() != "Host")
        {
            return Err(Error::InvalidRequest);
        }
        let mut policies = self.policies.clone();
        let mut expiries = HashMap::new();
        for grant in grants {
            grant.validate()?;
            if grant.organization != self.organization {
                return Err(Error::BoundaryViolation);
            }
            if grant.fields.membership != trusted.membership
                || request.resource() != Some(&uid("Host", grant.fields.host)?)
            {
                continue;
            }
            let id = unused_id(&policies, &grant.policy_id());
            let template_id = unused_id(&policies, &grant.template_id());
            let linked = grant.policy_set_with_ids(trusted.account, template_id, id.clone())?;
            // Cedar 4.4 can report a pre-rename policy id; insert fresh actual ids instead.
            policies.merge(&linked, false).map_err(|_| Error::InvalidConfiguration)?;
            expiries.insert(id, grant.fields.valid_until);
        }
        let response = self.evaluate(trusted, request, entities, &policies)?;
        if response.decision() == Decision::Deny {
            return Ok(ConnectAuthorization::Deny);
        }
        let mut not_after = 0;
        for reason in response.diagnostics().reason() {
            match expiries.get(reason) {
                None | Some(None) => return Ok(ConnectAuthorization::Allow { not_after: None }),
                Some(Some(expiry)) => not_after = not_after.max(*expiry),
            }
        }
        if not_after == 0 {
            return Err(Error::InvalidConfiguration);
        }
        Ok(ConnectAuthorization::Allow { not_after: Some(not_after) })
    }
}
