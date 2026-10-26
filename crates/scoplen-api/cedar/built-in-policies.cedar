// SPDX-License-Identifier: Apache-2.0
// Immutable guards and tenant-local role permits. The public authorization
// boundary additionally validates the hydrated graph and rejects every
// evaluation error; a raw Cedar Allow is not sufficient evidence.

forbid(principal, action, resource)
when {
    principal.status != "active" ||
    context.membership.status != "active" ||
    context.membership.account != principal ||
    context.membership.organization != context.organization
};

forbid(principal, action, resource is Organization)
when { resource != context.organization };

forbid(principal, action, resource)
when { resource has organization && resource.organization != context.organization };

forbid(principal, action == Action::"connect", resource)
when { context.device.account != principal };

forbid(principal, action == Action::"approve_access", resource)
when { context.requester != resource.requester || context.resource != resource.resource };

forbid(principal,
       action in [Action::"view_recording", Action::"monitor_session", Action::"terminate_session"],
       resource)
when { context.host != resource.host || context.account != resource.account };

// Owner: all organization administration and access actions.
permit(principal is Account,
       action in [Action::"view_inventory", Action::"connect", Action::"request_access", Action::"approve_access",
                  Action::"view_recording", Action::"monitor_session", Action::"terminate_session",
                  Action::"manage_organization", Action::"manage_inventory", Action::"manage_policy", Action::"manage_members",
                  Action::"manage_ca", Action::"manage_gateways", Action::"view_audit"], resource)
when { context.membership.roles.contains("owner") };

// Administrator: organization settings, inventory, policy, membership, CA, and gateways.
permit(principal is Account, action, resource)
when {
    context.membership.roles.contains("administrator") &&
    [Action::"view_inventory", Action::"manage_organization", Action::"manage_inventory", Action::"manage_policy", Action::"manage_members",
     Action::"manage_ca", Action::"manage_gateways"].contains(action)
};

// Security auditor: read-only security surfaces.
permit(principal is Account, action, resource)
when {
    context.membership.roles.contains("security_auditor") &&
    [Action::"view_inventory", Action::"view_audit", Action::"view_recording", Action::"monitor_session"].contains(action)
};

// Approver decisions are routed by organization policy before this check.
permit(principal is Account, action, resource)
when {
    context.membership.roles.contains("approver") && action == Action::"approve_access"
};

// A member needs explicit scoped inventory/access policies or current grants.
