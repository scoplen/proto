// SPDX-License-Identifier: Apache-2.0
//! The shared D-126 boundary around the maintained Cedar engine.

use std::{collections::HashSet, str::FromStr};

use cedar_policy::{
    Authorizer, Decision, Entities, Entity, EntityUid, EvalResult, PolicySet, Request, Schema,
    ValidationMode, Validator,
};
use scoplen_model::validate_uuid_v7;
use uuid::Uuid;

use super::{BUILT_IN_POLICIES, CEDAR_SCHEMA};

/// A current authenticated Account and selected Organization membership.
///
/// The consumer constructs this from verified authentication, trusted server time
/// and current durable state in the operation's authorized snapshot/transaction.
/// Construction checks identifiers, not authentication, freshness or database state.
/// Request JSON, JWT membership snapshots and global role unions are not sources
/// for these values or the entity attributes supplied to the authorizer.
#[derive(Clone, Debug)]
pub struct OrganizationAuthorizationContext {
    account: Uuid,
    organization: Uuid,
    membership: Uuid,
    now: i64,
}

impl OrganizationAuthorizationContext {
    /// Bind a verified Account to its current selected Organization membership.
    ///
    /// # Errors
    ///
    /// Returns an error for non-UUIDv7 identifiers or negative server time.
    pub fn new(
        account: Uuid,
        organization: Uuid,
        membership: Uuid,
        now: i64,
    ) -> Result<Self, OrganizationAuthorizationError> {
        for id in [account, organization, membership] {
            validate_uuid_v7(id).map_err(|_| OrganizationAuthorizationError::InvalidContext)?;
        }
        if now < 0 {
            return Err(OrganizationAuthorizationError::InvalidContext);
        }
        Ok(Self { account, organization, membership, now })
    }
}

/// An immutable schema, mandatory guards and policies owned by one Organization.
///
/// The consumer loads the custom policies from this Organization's current trusted
/// policy version. Templates and linked policies are preserved. No method can remove
/// or replace the built-in guards. Recreate the authorizer when that version changes.
pub struct OrganizationAuthorizer {
    organization: Uuid,
    schema: Schema,
    policies: PolicySet,
}

impl OrganizationAuthorizer {
    /// Validate and bind custom policies to their durable owning Organization.
    ///
    /// An empty policy set retains built-in roles. The supplied owner is trusted
    /// loader state; this function cannot discover ownership from arbitrary policy text.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid owner, malformed built-ins or any strict
    /// schema validation error in the combined policy set.
    pub fn new(
        organization: Uuid,
        custom_policies: &PolicySet,
    ) -> Result<Self, OrganizationAuthorizationError> {
        validate_uuid_v7(organization)
            .map_err(|_| OrganizationAuthorizationError::InvalidConfiguration)?;
        let schema = Schema::from_str(CEDAR_SCHEMA)
            .map_err(|_| OrganizationAuthorizationError::InvalidConfiguration)?;
        let mut policies = PolicySet::from_str(BUILT_IN_POLICIES)
            .map_err(|_| OrganizationAuthorizationError::InvalidConfiguration)?;
        // Rename colliding custom ids, including linked template ids, rather than
        // letting a custom policy replace a guard or silently dropping an instance.
        policies
            .merge(custom_policies, true)
            .map_err(|_| OrganizationAuthorizationError::InvalidConfiguration)?;
        if !Validator::new(schema.clone())
            .validate(&policies, ValidationMode::Strict)
            .validation_passed()
        {
            return Err(OrganizationAuthorizationError::InvalidConfiguration);
        }
        Ok(Self { organization, schema, policies })
    }

    /// Evaluate one mapped Organization action against a complete trusted graph.
    ///
    /// Both `Deny` and every error prohibit the operation. A successful `Allow`
    /// establishes this action only, for this supplied snapshot. Inventory use also
    /// requires a separate `view_inventory` decision; approval needs current routing
    /// and requester eligibility; connect needs current enrolled-device/grant checks.
    /// Consumers recheck authorization at durable commit and delivery boundaries.
    ///
    /// All referenced entities must be hydrated. Organization-owned entities in the
    /// graph must share the selected owner. Historical Session Accounts may differ
    /// from the principal; that attribution does not grant current membership.
    ///
    /// # Errors
    ///
    /// Returns a redacted error for an invalid request, entity graph, trusted binding
    /// or any Cedar evaluation error, even if another policy returns `Allow`.
    pub fn authorize(
        &self,
        trusted: &OrganizationAuthorizationContext,
        request: &Request,
        entities: &Entities,
    ) -> Result<Decision, OrganizationAuthorizationError> {
        if trusted.organization != self.organization {
            return Err(OrganizationAuthorizationError::BoundaryViolation);
        }
        let account = uid("Account", trusted.account)?;
        let organization = uid("Organization", trusted.organization)?;
        let membership = uid("Membership", trusted.membership)?;
        let context = request.context().ok_or(OrganizationAuthorizationError::InvalidRequest)?;
        if request.principal() != Some(&account)
            || context.get("organization") != Some(EvalResult::EntityUid(organization.clone()))
            || context.get("membership") != Some(EvalResult::EntityUid(membership.clone()))
            || context.get("now") != Some(EvalResult::Long(trusted.now))
        {
            return Err(OrganizationAuthorizationError::BoundaryViolation);
        }
        let request = Request::new(
            account.clone(),
            request.action().cloned().ok_or(OrganizationAuthorizationError::InvalidRequest)?,
            request.resource().cloned().ok_or(OrganizationAuthorizationError::InvalidRequest)?,
            context.clone(),
            Some(&self.schema),
        )
        .map_err(|_| OrganizationAuthorizationError::InvalidRequest)?;
        // Never trust that the caller constructed these with this schema.
        let entities = Entities::from_entities(entities.iter().cloned(), Some(&self.schema))
            .map_err(|_| OrganizationAuthorizationError::InvalidEntities)?;
        validate_graph(&entities, &organization)?;
        let principal = get_entity(&entities, &account)?;
        let member = get_entity(&entities, &membership)?;
        if attribute(principal, "status")? != EvalResult::String("active".into())
            || attribute(member, "status")? != EvalResult::String("active".into())
            || reference(member, "account")? != account
            || reference(member, "organization")? != organization
        {
            return Err(OrganizationAuthorizationError::BoundaryViolation);
        }
        let resource = get_entity(
            &entities,
            request.resource().ok_or(OrganizationAuthorizationError::InvalidRequest)?,
        )?;
        match request.action().map(|action| action.id().unescaped()) {
            Some("connect") => {
                let device = context_reference(&request, "device")?;
                if reference(get_entity(&entities, &device)?, "account")? != account {
                    return Err(OrganizationAuthorizationError::BoundaryViolation);
                }
            }
            Some("approve_access") => {
                validate_context_reference(&request, resource, "requester", "requester")?;
                validate_context_reference(&request, resource, "resource", "resource")?;
            }
            Some("view_recording" | "monitor_session" | "terminate_session") => {
                validate_context_reference(&request, resource, "host", "host")?;
                validate_context_reference(&request, resource, "account", "account")?;
            }
            _ => {}
        }
        let response = Authorizer::new().is_authorized(&request, &self.policies, &entities);
        if response.diagnostics().errors().next().is_some() {
            return Err(OrganizationAuthorizationError::Evaluation);
        }
        Ok(response.decision())
    }
}

/// Redacted authorization failures; none permits an operation or discloses a resource.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum OrganizationAuthorizationError {
    /// The schema, owner or combined policy set is invalid.
    #[error("invalid organization authorization configuration")]
    InvalidConfiguration,
    /// The trusted identity or server time has an invalid form.
    #[error("invalid organization authorization context")]
    InvalidContext,
    /// The request does not match the canonical action schema.
    #[error("invalid organization authorization request")]
    InvalidRequest,
    /// The graph does not match the canonical entity schema.
    #[error("invalid organization authorization entities")]
    InvalidEntities,
    /// A required current-state or tenant binding is absent or mismatched.
    #[error("organization authorization boundary denied")]
    BoundaryViolation,
    /// At least one policy could not be evaluated completely.
    #[error("organization authorization evaluation failed")]
    Evaluation,
}

fn uid(kind: &str, id: Uuid) -> Result<EntityUid, OrganizationAuthorizationError> {
    format!("{kind}::\"{id}\"").parse().map_err(|_| OrganizationAuthorizationError::InvalidContext)
}

fn get_entity<'a>(
    entities: &'a Entities,
    uid: &EntityUid,
) -> Result<&'a Entity, OrganizationAuthorizationError> {
    entities.get(uid).ok_or(OrganizationAuthorizationError::BoundaryViolation)
}

fn attribute(entity: &Entity, name: &str) -> Result<EvalResult, OrganizationAuthorizationError> {
    entity
        .attr(name)
        .ok_or(OrganizationAuthorizationError::InvalidEntities)?
        .map_err(|_| OrganizationAuthorizationError::InvalidEntities)
}

fn reference(entity: &Entity, name: &str) -> Result<EntityUid, OrganizationAuthorizationError> {
    match attribute(entity, name)? {
        EvalResult::EntityUid(uid) => Ok(uid),
        _ => Err(OrganizationAuthorizationError::InvalidEntities),
    }
}

fn context_reference(
    request: &Request,
    name: &str,
) -> Result<EntityUid, OrganizationAuthorizationError> {
    match request.context().and_then(|context| context.get(name)) {
        Some(EvalResult::EntityUid(uid)) => Ok(uid),
        _ => Err(OrganizationAuthorizationError::InvalidRequest),
    }
}

fn validate_context_reference(
    request: &Request,
    resource: &Entity,
    context_name: &str,
    attribute_name: &str,
) -> Result<(), OrganizationAuthorizationError> {
    if context_reference(request, context_name)? != reference(resource, attribute_name)? {
        return Err(OrganizationAuthorizationError::BoundaryViolation);
    }
    Ok(())
}

fn validate_graph(
    entities: &Entities,
    organization: &EntityUid,
) -> Result<(), OrganizationAuthorizationError> {
    get_entity(entities, organization)?;
    let mut ids = HashSet::new();
    let mut memberships = HashSet::new();
    for entity in entities.iter() {
        let entity_uid = entity.uid();
        let kind = entity_uid.type_name().to_string();
        if kind == "Action" {
            continue;
        }
        let id = entity_uid.id().unescaped();
        let parsed =
            Uuid::parse_str(id).map_err(|_| OrganizationAuthorizationError::InvalidEntities)?;
        if validate_uuid_v7(parsed).is_err()
            || parsed.to_string() != id
            || !ids.insert(id.to_owned())
        {
            return Err(OrganizationAuthorizationError::InvalidEntities);
        }
        let references: &[&str] = match kind.as_str() {
            "Account" => &[],
            "Organization" if &entity_uid == organization => &[],
            "Membership" => &["organization", "account", "groups"],
            "Group" | "GatewayNetwork" | "Route" | "Snippet" => &["organization"],
            "Device" => &["account"],
            "Host" => &["organization", "host_groups", "gateway_network"],
            "HostGroup" => &["organization", "parents"],
            "AccessProfile" | "TrustRecord" => &["organization", "host"],
            "AccessRequest" => &["organization", "requester", "resource"],
            "Session" => &["organization", "host", "account"],
            _ => return Err(OrganizationAuthorizationError::BoundaryViolation),
        };
        if references.contains(&"organization")
            && reference(entity, "organization")? != *organization
        {
            return Err(OrganizationAuthorizationError::BoundaryViolation);
        }
        if kind == "Membership"
            && !memberships
                .insert((reference(entity, "organization")?, reference(entity, "account")?))
        {
            return Err(OrganizationAuthorizationError::InvalidEntities);
        }
        if kind == "Group"
            && !matches!(attribute(entity, "source")?, EvalResult::String(source) if source == "local" || source == "IdP")
        {
            return Err(OrganizationAuthorizationError::InvalidEntities);
        }
        for name in references {
            let Some(value) = entity.attr(name) else { continue };
            match value.map_err(|_| OrganizationAuthorizationError::InvalidEntities)? {
                EvalResult::EntityUid(uid) => {
                    get_entity(entities, &uid)?;
                }
                EvalResult::Set(values) => {
                    for value in values.iter() {
                        let EvalResult::EntityUid(uid) = value else {
                            return Err(OrganizationAuthorizationError::InvalidEntities);
                        };
                        get_entity(entities, uid)?;
                    }
                }
                _ => return Err(OrganizationAuthorizationError::InvalidEntities),
            }
        }
    }
    Ok(())
}
