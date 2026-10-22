// SPDX-License-Identifier: Apache-2.0
// Built-in role policies. Organization membership and role claims are supplied
// by the control plane entity loader; no client may widen these policies.

// Owner: all organization administration and access actions.
permit(principal is Account,
       action in [Action::"connect", Action::"request_access", Action::"approve_access",
                  Action::"view_recording", Action::"monitor_session", Action::"terminate_session",
                  Action::"manage_inventory", Action::"manage_policy", Action::"manage_members",
                  Action::"manage_ca", Action::"manage_gateways", Action::"view_audit"], resource)
when { principal.groups.contains(Group::"owner") };

// Administrator: inventory, policy, membership, CA, and gateway administration.
permit(principal is Account, action, resource)
when {
    principal.groups.contains(Group::"administrator") &&
    [Action::"manage_inventory", Action::"manage_policy", Action::"manage_members",
     Action::"manage_ca", Action::"manage_gateways"].contains(action)
};

// Security auditor: read-only security surfaces.
permit(principal is Account, action, resource)
when {
    principal.groups.contains(Group::"security_auditor") &&
    [Action::"view_audit", Action::"view_recording", Action::"monitor_session"].contains(action)
};

// Approver decisions are routed by organization policy before this check.
permit(principal is Account, action, resource)
when {
    principal.groups.contains(Group::"approver") && action == Action::"approve_access"
};

// Members can request access and connect only after the policy engine has
// checked the request context and grant state.
permit(principal is Account, action, resource)
when {
    principal.groups.contains(Group::"member") &&
    [Action::"request_access", Action::"connect"].contains(action)
};

// Deployment status comes from current durable state, never caller-controlled JWT claims.
permit(principal is Operator, action == Action::"issuePersonalInvitation",
       resource == Deployment::"self")
when { principal.status == "active" };
