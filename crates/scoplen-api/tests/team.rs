// SPDX-License-Identifier: Apache-2.0
use scoplen_api::{
    organization::{OrganizationCodecError, OrganizationListQuery},
    team::*,
};
use scoplen_crypto::{TeamInvitationPassword, TeamInvitationVerifier};
use uuid::Uuid;

fn id(n: u16) -> Uuid {
    Uuid::parse_str(&format!("019bdad6-b800-7000-8000-{n:012}")).unwrap()
}

#[test]
fn public_role_and_status_parsers_preserve_exact_storage_projection_values() {
    assert_eq!(TeamRole::parse("owner"), Ok(TeamRole::Owner));
    assert_eq!(TeamInvitationStatus::parse("locked"), Ok(TeamInvitationStatus::Locked));
    assert_eq!(TeamMemberStatus::parse("removed"), Ok(TeamMemberStatus::Removed));
    for value in ["Owner", "owner ", "custom"] {
        assert!(TeamRole::parse(value).is_err());
    }
    for value in ["Locked", "pending ", "consumed"] {
        assert!(TeamInvitationStatus::parse(value).is_err());
    }
    for value in ["Active", "removed ", "deprovisioned"] {
        assert!(TeamMemberStatus::parse(value).is_err());
    }
}

fn invitation(n: u16) -> TeamInvitationResource {
    TeamInvitationResource {
        id: id(n),
        etag: "\"current\"".into(),
        created_at: "2026-11-01T00:00:00Z".into(),
        updated_at: "2026-11-01T00:00:00Z".into(),
        organization_id: id(1),
        organization_name: "Operations".into(),
        recipient_account_id: id(2),
        recipient_username: "recipient".into(),
        roles: vec![TeamRole::Member],
        issuer_account_id: id(3),
        expires_at: "2026-11-02T00:00:00Z".into(),
        status: TeamInvitationStatus::Pending,
        membership_id: None,
    }
}

fn member(n: u16) -> TeamMemberResource {
    TeamMemberResource {
        id: id(n),
        etag: "\"member\"".into(),
        created_at: "2026-11-01T00:00:00Z".into(),
        updated_at: "2026-11-01T00:00:00Z".into(),
        organization_id: id(1),
        account_id: id(2),
        username: "recipient".into(),
        roles: vec![TeamRole::Member],
        status: TeamMemberStatus::Active,
    }
}

#[test]
fn invitation_requests_roundtrip_with_canonical_order_and_redacted_secret_ownership() {
    let password = TeamInvitationPassword::parse(b"1ABCDXYZ").unwrap();
    let request = TeamInvitationCreateRequest {
        invitation_id: id(4),
        recipient_username: "recipient".into(),
        roles: vec![TeamRole::Member, TeamRole::Administrator],
        password_verifier: password.verifier("https://sync.example.test", &id(1), &id(4)).unwrap(),
    };
    let wire = request.to_json().unwrap();
    let decoded = TeamInvitationCreateRequest::from_json(wire.as_bytes()).unwrap();
    assert_eq!(decoded.roles, [TeamRole::Administrator, TeamRole::Member]);
    assert_eq!(decoded.password_verifier, request.password_verifier);
    assert_eq!(decoded.to_json().unwrap(), wire);
    let text = std::str::from_utf8(wire.as_bytes()).unwrap();
    assert!(text.starts_with(&format!("{{\"invitation_id\":\"{}\",\"recipient_username\":\"recipient\",\"roles\":[\"administrator\",\"member\"],\"password_verifier\":", id(4))));
    assert!(!format!("{request:?} {wire:?}").contains("recipient"));
    let accept = TeamInvitationAcceptRequest { password };
    let encoded = accept.to_json().unwrap();
    assert_eq!(encoded.as_bytes(), b"{\"password\":\"1ABCDXYZ\"}");
    assert_eq!(TeamInvitationAcceptRequest::from_json(encoded.as_bytes()).unwrap(), accept);
    assert!(!format!("{accept:?} {encoded:?}").contains("1ABCDXYZ"));
}

#[test]
fn strict_creation_and_acceptance_refuse_aliases_unknowns_duplicates_and_overflow() {
    let valid = TeamInvitationCreateRequest {
        invitation_id: id(4),
        recipient_username: "recipient".into(),
        roles: vec![TeamRole::Member],
        password_verifier: TeamInvitationVerifier::from_bytes([1; 32]),
    }
    .to_json()
    .unwrap();
    let text = std::str::from_utf8(valid.as_bytes()).unwrap();
    for malformed in [
        text.replace("\"recipient\"", "\"Recipient\""),
        text.replace("\"member\"", "\"member\",\"member\""),
        text.replace("\"member\"", "\"custom\""),
        text.replace("\"invitation_id\":", "\"extra\":null,\"invitation_id\":"),
        text.replace(
            "\"recipient_username\":",
            "\"recipient_username\":\"other\",\"recipient_username\":",
        ),
        text.replace("019bdad6", "019BDAD6"),
        format!("{text}{}", " ".repeat(MAX_INVITATION_CREATE_BYTES)),
    ] {
        assert!(TeamInvitationCreateRequest::from_json(malformed.as_bytes()).is_err());
    }
    for malformed in [
        "{\"password\":\"1ABCDXYZ\",\"password\":\"1ABCDXYZ\"}",
        "{\"password\":\"1ABCDXYZ\",\"role\":\"owner\"}",
        "{\"password\":\"1abcdxyz\"}",
        "{\"password\":\"1ABCDXYI\"}",
        "{\"password\":\"1ABCDXYZ \"}",
        "{\"password\":null}",
        "{\"password\":[1,2,3]}",
        "{\"password\":\"1ABCDXYZ\",\"extra\":{\"x\":1,\"x\":2}}",
    ] {
        assert!(TeamInvitationAcceptRequest::from_json(malformed.as_bytes()).is_err());
    }
    assert_eq!(
        TeamInvitationAcceptRequest::from_json(&vec![b' '; MAX_INVITATION_ACCEPT_BYTES + 1]),
        Err(OrganizationCodecError::TooLarge)
    );
}

#[test]
fn public_link_never_carries_a_password_or_normalizes_an_origin_or_uuid() {
    let value = TeamInvitationLink {
        origin: "https://sync.example.test:9443".into(),
        organization_id: id(1),
        invitation_id: id(4),
    };
    let url = value.to_url().unwrap();
    assert_eq!(TeamInvitationLink::parse(&url).unwrap(), value);
    for malformed in [
        format!("{url}&password=1ABCDXYZ"),
        url.replace("https://", "http://"),
        url.replace("#organization=", "?organization="),
        url.replace("019bdad6", "019BDAD6"),
        url.replace("/join-team#", "/join-team/#"),
        url.replace("sync.example.test", "SYNC.example.test"),
        url.replace("&invitation=", "&other="),
    ] {
        assert!(TeamInvitationLink::parse(&malformed).is_err(), "link alias accepted");
    }
}

#[test]
fn invitation_projection_requires_recipient_context_and_exact_http_metadata() {
    let value = invitation(4);
    let bytes = value.to_json().unwrap();
    assert_eq!(
        TeamInvitationResource::from_http_json(
            &bytes,
            Some("\"current\""),
            Some("no-store"),
            Some("no-cache")
        )
        .unwrap(),
        value
    );
    assert!(
        TeamInvitationResource::from_http_json(
            &bytes,
            Some("\"other\""),
            Some("no-store"),
            Some("no-cache")
        )
        .is_err()
    );
    assert!(
        TeamInvitationResource::from_http_json(&bytes, Some("\"current\""), None, Some("no-cache"))
            .is_err()
    );
    value.validate_for_recipient(id(2), id(1), id(4)).unwrap();
    for (account, organization, invitation) in
        [(id(7), id(1), id(4)), (id(2), id(7), id(4)), (id(2), id(1), id(7))]
    {
        assert_eq!(
            value.validate_for_recipient(account, organization, invitation),
            Err(OrganizationCodecError::Context)
        );
    }
    let mut accepted = value;
    accepted.status = TeamInvitationStatus::Accepted;
    assert!(accepted.to_json().is_err());
    accepted.membership_id = Some(id(8));
    assert_eq!(TeamInvitationResource::from_json(&accepted.to_json().unwrap()).unwrap(), accepted);
}

#[test]
fn member_edits_do_not_encode_removal_or_duplicate_owner_grants() {
    let value = TeamMemberUpdateRequest {
        roles: vec![TeamRole::Member, TeamRole::Administrator],
        status: TeamMemberStatus::Suspended,
    };
    assert_eq!(
        value.to_json().unwrap(),
        b"{\"roles\":[\"administrator\",\"member\"],\"status\":\"suspended\"}"
    );
    assert_eq!(
        TeamMemberUpdateRequest::from_json(&value.to_json().unwrap()).unwrap().roles,
        [TeamRole::Administrator, TeamRole::Member]
    );
    assert!(
        TeamMemberUpdateRequest { status: TeamMemberStatus::Removed, ..value.clone() }
            .to_json()
            .is_err()
    );
    assert!(
        TeamMemberUpdateRequest { roles: vec![TeamRole::Owner, TeamRole::Owner], ..value }
            .to_json()
            .is_err()
    );
    let member = member(8);
    assert_eq!(TeamMemberResource::from_json(&member.to_json().unwrap()).unwrap(), member);
    assert_eq!(member.validate_for_organization(id(9)), Err(OrganizationCodecError::Context));
}

#[test]
fn directory_pages_reject_foreign_repeated_or_over_budget_original_resources() {
    let page =
        TeamInvitationPage { items: vec![invitation(4), invitation(5)], next_cursor: Some(id(5)) };
    let bytes = page.to_json().unwrap();
    assert_eq!(TeamInvitationPage::from_json(&bytes).unwrap(), page);
    page.validate_for_organization(id(1), OrganizationListQuery { limit: 2, cursor: Some(id(3)) })
        .unwrap();
    assert!(
        page.validate_for_organization(id(1), OrganizationListQuery { limit: 1, cursor: None })
            .is_err()
    );
    assert!(
        page.validate_for_organization(
            id(1),
            OrganizationListQuery { limit: 2, cursor: Some(id(4)) }
        )
        .is_err()
    );
    assert!(page.validate_for_organization(id(2), OrganizationListQuery::default()).is_err());
    assert!(
        TeamInvitationPage { items: vec![invitation(4), invitation(4)], next_cursor: None }
            .to_json()
            .is_err()
    );
    assert!(TeamInvitationPage { items: Vec::new(), next_cursor: Some(id(5)) }.to_json().is_err());
    let mut resource = String::from_utf8(invitation(4).to_json().unwrap()).unwrap();
    resource.pop();
    let oversized = format!(
        "{{\"items\":[{resource},\"extra\":\"{}\"}}],\"next_cursor\":null}}",
        " ".repeat(4096)
    );
    assert_eq!(
        TeamInvitationPage::from_json(oversized.as_bytes()),
        Err(OrganizationCodecError::TooLarge)
    );
    let member_page = TeamMemberPage { items: vec![member(8)], next_cursor: None };
    assert_eq!(TeamMemberPage::from_json(&member_page.to_json().unwrap()).unwrap(), member_page);
    member_page.validate_for_organization(id(1), OrganizationListQuery::default()).unwrap();
    assert!(
        member_page.validate_for_organization(id(2), OrganizationListQuery::default()).is_err()
    );
}

#[test]
fn historical_receipts_bind_echoed_ids_without_claiming_current_membership() {
    let acceptance = TeamAcceptanceReceipt {
        invitation_id: id(4),
        organization_id: id(1),
        account_id: id(2),
        membership_id: id(8),
        accepted_at: "2026-11-01T00:00:00Z".into(),
    };
    assert_eq!(
        TeamAcceptanceReceipt::from_json(&acceptance.to_json().unwrap()).unwrap(),
        acceptance
    );
    acceptance.validate_for_request(id(2), id(1), id(4)).unwrap();
    assert_eq!(
        acceptance.validate_for_request(id(3), id(1), id(4)),
        Err(OrganizationCodecError::Context)
    );
    let dissolve = TeamDissolveRequest { organization_id: id(1) };
    assert_eq!(TeamDissolveRequest::from_json(&dissolve.to_json().unwrap()).unwrap(), dissolve);
    assert_eq!(dissolve.validate_for_organization(id(2)), Err(OrganizationCodecError::Context));
    let receipt = TeamDissolutionReceipt {
        organization_id: id(1),
        dissolved_at: "2026-11-01T00:00:00Z".into(),
    };
    assert_eq!(TeamDissolutionReceipt::from_json(&receipt.to_json().unwrap()).unwrap(), receipt);
    receipt.validate_for_organization(id(1)).unwrap();
    assert_eq!(receipt.validate_for_organization(id(2)), Err(OrganizationCodecError::Context));
}
