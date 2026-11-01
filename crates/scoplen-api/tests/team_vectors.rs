// SPDX-License-Identifier: Apache-2.0
use scoplen_api::{ProblemDetails, organization::OrganizationCodecError, team::*};
use scoplen_test_vectors::VectorDocument;

fn decode(kind: &str, bytes: &[u8]) -> Result<Vec<u8>, OrganizationCodecError> {
    match kind {
        "create" => TeamInvitationCreateRequest::from_json(bytes)?
            .to_json()
            .map(|value| value.as_bytes().to_vec()),
        "accept" => TeamInvitationAcceptRequest::from_json(bytes)?
            .to_json()
            .map(|value| value.as_bytes().to_vec()),
        "invitation" => TeamInvitationResource::from_json(bytes)?.to_json(),
        "member" => TeamMemberResource::from_json(bytes)?.to_json(),
        "update" => TeamMemberUpdateRequest::from_json(bytes)?.to_json(),
        "receipt" => TeamAcceptanceReceipt::from_json(bytes)?.to_json(),
        "dissolve" => TeamDissolveRequest::from_json(bytes)?.to_json(),
        "dissolved" => TeamDissolutionReceipt::from_json(bytes)?.to_json(),
        "invitation_page" => TeamInvitationPage::from_json(bytes)?.to_json(),
        "member_page" => TeamMemberPage::from_json(bytes)?.to_json(),
        "link" => TeamInvitationLink::parse(
            std::str::from_utf8(bytes).map_err(|_| OrganizationCodecError::InvalidJson)?,
        )?
        .to_url()
        .map(String::into_bytes),
        "problem" => {
            let problem = ProblemDetails::from_json(bytes, 4096)
                .map_err(|_| OrganizationCodecError::InvalidJson)?;
            assert!(problem.code.is_known());
            serde_json::to_vec(&problem).map_err(|_| OrganizationCodecError::InvalidJson)
        }
        _ => panic!("unknown team vector kind {kind}"),
    }
}

#[test]
fn all_independent_d136_wire_vectors_use_public_codecs_and_exact_bounds() {
    let document =
        VectorDocument::parse_str(include_str!("../../../vectors/team-membership.json")).unwrap();
    assert_eq!(document.vectors.len(), 109);
    for vector in document.vectors {
        let kind = vector.kind.strip_prefix("team.").unwrap();
        if kind == "bound" {
            let recipe: serde_json::Value = serde_json::from_str(&vector.input).unwrap();
            let base = recipe["base"].as_str().unwrap();
            let bound = usize::try_from(recipe["bytes"].as_u64().unwrap()).unwrap();
            let input = " ".repeat(bound - base.len()) + base;
            assert_eq!(input.len(), bound);
            assert_eq!(
                decode(recipe["kind"].as_str().unwrap(), input.as_bytes()).is_ok(),
                vector.expected == "accepted",
                "{}",
                vector.id
            );
        } else if let Some(kind) = kind.strip_suffix(".reject") {
            assert!(decode(kind, vector.input.as_bytes()).is_err(), "{}", vector.id);
        } else {
            let actual = decode(kind, vector.input.as_bytes())
                .unwrap_or_else(|error| panic!("{}: {error}", vector.id));
            assert_eq!(actual, vector.expected.as_bytes(), "{}", vector.id);
            assert_eq!(decode(kind, &actual).unwrap(), actual, "{}", vector.id);
        }
    }
}
