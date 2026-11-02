// SPDX-License-Identifier: Apache-2.0
use scoplen_api::{
    auth::{DeviceAccessOperation, DeviceAccessScope},
    sync::{
        MAX_SYNC_ORGANIZATION_ACK_REQUEST_BYTES, MAX_SYNC_ORGANIZATION_VIEW_QUERY_BYTES,
        OrganizationVaultContext, SessionVault, SyncAckRequest, SyncAckResponse, SyncChange,
        SyncLimits, SyncNotification, SyncNotificationContext, SyncNotificationReady,
        SyncOrganizationAckRequest, SyncOrganizationAckResponse, SyncOrganizationViewQuery,
        SyncOrganizationViewResponse, SyncReadLimits, SyncSessionResponse, VaultKind,
    },
};
use scoplen_model::{
    FieldEntry, FieldPath, Hlc, Object, ObjectType, Tombstone,
    cbor::{self, Value},
};
use uuid::Uuid;

fn id(n: u8) -> Uuid {
    Uuid::from_bytes([0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, n])
}

fn source() -> OrganizationVaultContext {
    OrganizationVaultContext { organization: id(1), view_revision: 7 }
}

fn query() -> SyncOrganizationViewQuery {
    SyncOrganizationViewQuery { view_revision: 7, after: 0, limit: 10 }
}

fn page() -> SyncOrganizationViewResponse {
    let mut object = Object::new(id(3), ObjectType::HOST, 1).unwrap();
    for (field, value) in [(1, "Example"), (2, "host.example")] {
        object
            .insert(
                FieldPath::Field(field),
                FieldEntry::new(Value::Text(value.into()), Hlc::from_wire(1).unwrap(), id(4))
                    .unwrap(),
            )
            .unwrap();
    }
    SyncOrganizationViewResponse {
        organization: id(1),
        vault: id(2),
        view_revision: 7,
        objects: vec![SyncChange {
            object_id: id(3),
            seq: 5,
            payload: object.encode().unwrap(),
            tombstone: false,
            signer_device_id: None,
        }],
        next_cursor: 8,
        more: false,
    }
}

fn encode(fields: Vec<(&str, Value)>) -> Vec<u8> {
    cbor::encode(&Value::Map(
        fields.into_iter().map(|(key, value)| (Value::Text(key.into()), value)).collect(),
    ))
    .unwrap()
}

fn extended(input: &[u8], name: &str, value: Value) -> Vec<u8> {
    let Value::Map(mut fields) = cbor::decode(input).unwrap() else { panic!("map") };
    fields.push((Value::Text(name.into()), value));
    cbor::encode(&Value::Map(fields)).unwrap()
}

#[test]
fn view_query_is_strict_canonical_and_uses_exact_existing_read_scope() {
    let value = query();
    assert_eq!(value.to_query().unwrap(), "revision=7&after=0&limit=10");
    assert_eq!(SyncOrganizationViewQuery::from_query("limit=10&after=0&revision=7"), Ok(value));
    let maximum =
        SyncOrganizationViewQuery { view_revision: u64::MAX, after: u64::MAX, limit: 1000 };
    assert_eq!(maximum.to_query().unwrap().len(), MAX_SYNC_ORGANIZATION_VIEW_QUERY_BYTES);
    assert_eq!(SyncOrganizationViewQuery::from_query(&maximum.to_query().unwrap()), Ok(maximum));
    for input in [
        "revision=0&after=0&limit=10",
        "revision=07&after=0&limit=10",
        "revision=7&after=00&limit=10",
        "revision=7&after=0&limit=0",
        "revision=7&after=0&limit=1001",
        "revision=7&after=0&limit=10&revision=7",
        "revision=7&after=0",
        "after=0&limit=10",
        "revision=7&after=0&limit=10&other=1",
        "revision=+7&after=0&limit=10",
        "revision=7&after=0&limit=10&",
        "revision=18446744073709551616&after=0&limit=10",
    ] {
        assert!(SyncOrganizationViewQuery::from_query(input).is_err(), "{input}");
    }
    let operation =
        DeviceAccessOperation::from_route("GET", "/sync/v1/vaults/{vault}/view").unwrap();
    assert_eq!(operation.accepted_scopes(), &[DeviceAccessScope::SyncRead]);
    assert!(DeviceAccessOperation::from_route("POST", "/sync/v1/vaults/{vault}/view").is_none());
}

#[test]
fn view_page_binds_source_revision_and_pagination_before_publication() {
    let value = page();
    let bytes = value.to_cbor().unwrap();
    assert_eq!(SyncOrganizationViewResponse::from_cbor(&bytes), Ok(value.clone()));
    value.validate_for_query(source(), id(2), &query()).unwrap();
    assert!(value.validate_for_query(source(), id(4), &query()).is_err());
    assert!(
        value
            .validate_for_query(
                OrganizationVaultContext { organization: id(4), ..source() },
                id(2),
                &query()
            )
            .is_err()
    );
    assert!(
        value
            .validate_for_query(
                OrganizationVaultContext { view_revision: 8, ..source() },
                id(2),
                &query()
            )
            .is_err()
    );
    assert!(
        value
            .validate_for_query(
                source(),
                id(2),
                &SyncOrganizationViewQuery { view_revision: 8, ..query() }
            )
            .is_err()
    );
    assert!(
        value
            .validate_for_query(source(), id(2), &SyncOrganizationViewQuery { after: 5, ..query() })
            .is_err()
    );
    let mut partial = value.clone();
    partial.more = true;
    assert!(partial.to_cbor().is_err());
    partial.next_cursor = 5;
    partial.validate_for_query(source(), id(2), &query()).unwrap();
    partial.objects.push(partial.objects[0].clone());
    assert!(partial.to_cbor().is_err());
    let mut empty = value;
    empty.objects.clear();
    empty.validate_for_query(source(), id(2), &query()).unwrap();
    empty.more = true;
    assert!(empty.to_cbor().is_err());
}

#[test]
fn organization_view_rejects_encrypted_signed_deleted_or_mismatched_objects() {
    for mutation in 0..7 {
        let mut value = page();
        match mutation {
            0 => value.objects[0].tombstone = true,
            1 => value.objects[0].signer_device_id = Some(id(4)),
            2 => value.objects[0].payload = vec![0x41, 0],
            3 => value.objects[0].object_id = id(4),
            4 => value.view_revision = 0,
            5 => value.organization = Uuid::nil(),
            _ => {
                let mut object = Object::decode(&value.objects[0].payload).unwrap();
                object.set_tombstone(Some(
                    Tombstone::new(Hlc::from_wire(2).unwrap(), id(4)).unwrap(),
                ));
                value.objects[0].payload = object.encode().unwrap();
            }
        }
        assert!(value.to_cbor().is_err());
    }
}

#[test]
fn exact_view_body_and_payload_budgets_cover_extensions_and_empty_pages() {
    for mut value in [page(), SyncOrganizationViewResponse { objects: vec![], ..page() }] {
        for revision in [1, 24, u64::MAX] {
            value.view_revision = revision;
            let bytes = value.to_cbor().unwrap();
            let limits = SyncReadLimits { max_envelope_bytes: 4096, max_body_bytes: bytes.len() };
            assert_eq!(value.to_cbor_with_limits(limits).unwrap(), bytes);
            assert_eq!(
                SyncOrganizationViewResponse::from_cbor_with_limits(&bytes, limits),
                Ok(value.clone())
            );
            let short = SyncReadLimits { max_body_bytes: bytes.len() - 1, ..limits };
            assert!(value.to_cbor_with_limits(short).is_err());
            assert!(SyncOrganizationViewResponse::from_cbor_with_limits(&bytes, short).is_err());
            let more = extended(&bytes, "future", Value::Text("extension".into()));
            assert!(SyncOrganizationViewResponse::from_cbor_with_limits(&more, limits).is_err());
            assert_eq!(SyncOrganizationViewResponse::from_cbor(&more), Ok(value.clone()));
        }
    }
    let value = page();
    let limit = value.objects[0].payload.len() - 1;
    assert!(
        value
            .to_cbor_with_limits(SyncReadLimits { max_envelope_bytes: limit, max_body_bytes: 4096 })
            .is_err()
    );
}

#[test]
fn organization_ack_is_revision_bound_and_does_not_change_personal_ack_wire() {
    let request = SyncOrganizationAckRequest { cursor: u64::MAX, view_revision: u64::MAX };
    let bytes = request.to_cbor().unwrap();
    assert_eq!(bytes.len(), MAX_SYNC_ORGANIZATION_ACK_REQUEST_BYTES);
    assert_eq!(SyncOrganizationAckRequest::from_cbor(&bytes), Ok(request));
    let response = SyncOrganizationAckResponse {
        cursor: request.cursor,
        view_revision: request.view_revision,
    };
    assert_eq!(response.to_cbor().unwrap(), bytes);
    response.validate_for_request(&request).unwrap();
    assert!(
        SyncOrganizationAckResponse { view_revision: 1, ..response }
            .validate_for_request(&request)
            .is_err()
    );
    assert!(
        SyncOrganizationAckResponse { cursor: 0, ..response }
            .validate_for_request(&request)
            .is_err()
    );
    let extension = extended(&bytes, "future", Value::Bool(true));
    assert!(SyncOrganizationAckRequest::from_cbor(&extension).is_err());
    assert_eq!(SyncOrganizationAckResponse::from_cbor(&extension), Ok(response));
    assert!(SyncOrganizationAckRequest { cursor: 0, view_revision: 0 }.to_cbor().is_err());
    assert!(
        SyncOrganizationAckResponse::from_cbor(&SyncAckRequest { cursor: 0 }.to_cbor().unwrap())
            .is_err()
    );
    let personal = SyncAckRequest { cursor: 5 }.to_cbor().unwrap();
    assert_eq!(personal, encode(vec![("cursor", Value::UInt(5))]));
    assert_eq!(SyncAckResponse::from_cbor(&personal), Ok(SyncAckResponse { cursor: 5 }));
}

fn session(kind: VaultKind, organization: Option<OrganizationVaultContext>) -> SyncSessionResponse {
    SyncSessionResponse {
        server_version: "0.1.0".into(),
        max_model_version: 1,
        limits: SyncLimits {
            max_envelope_bytes: 266_240,
            max_batch_objects: 500,
            max_batch_bytes: 4_194_304,
            max_objects_per_vault: 100_000,
            max_shared_vaults_per_account: 1_000,
            max_members_per_shared_vault: 1_000,
            write_requests_per_second: 50,
            write_burst: 200,
        },
        vaults: vec![SessionVault {
            id: id(2),
            kind,
            seq: 0,
            key_epoch: 1,
            rotation_pending: false,
            organization,
        }],
    }
}

#[test]
fn organization_descriptors_require_owner_and_positive_revision_in_exact_budget() {
    let mut value = session(VaultKind::Organization, Some(source()));
    let bytes = value.to_cbor().unwrap();
    assert_eq!(value.to_cbor_with_body_limit(bytes.len()).unwrap(), bytes);
    assert!(value.to_cbor_with_body_limit(bytes.len() - 1).is_err());
    assert_eq!(SyncSessionResponse::from_cbor(&bytes), Ok(value.clone()));
    assert!(session(VaultKind::Organization, None).to_cbor().is_err());
    assert!(session(VaultKind::Personal, Some(source())).to_cbor().is_err());
    value.vaults[0].organization.as_mut().unwrap().view_revision = 0;
    assert!(value.to_cbor().is_err());
    let Value::Map(mut fields) = cbor::decode(&bytes).unwrap() else { panic!("session map") };
    let (_, Value::Array(vaults)) =
        fields.iter_mut().find(|(key, _)| key == &Value::Text("vaults".into())).unwrap()
    else {
        panic!("vault list")
    };
    let Value::Map(descriptor) = &mut vaults[0] else { panic!("descriptor") };
    descriptor.retain(|(key, _)| key != &Value::Text("organization".into()));
    assert!(SyncSessionResponse::from_cbor(&cbor::encode(&Value::Map(fields)).unwrap()).is_err());
    let future = session(VaultKind::Unknown("future".into()), None);
    assert_eq!(SyncSessionResponse::from_cbor(&future.to_cbor().unwrap()), Ok(future));
}

#[test]
fn team_hints_have_exact_fields_and_cannot_mix_notification_states() {
    for event in [
        SyncNotification::MembershipsChanged,
        SyncNotification::OrganizationViewChanged {
            organization: id(1),
            vault: id(2),
            view_revision: 7,
        },
    ] {
        let bytes = event.to_cbor().unwrap();
        assert_eq!(SyncNotification::from_cbor(&bytes), Ok(event.clone()));
        assert_eq!(
            SyncNotification::from_cbor(&extended(&bytes, "future", Value::Bool(true))),
            Ok(event)
        );
        for key in [
            "seq",
            "rotation_pending",
            "device_revoked",
            "htm",
            "authenticated",
            "access_token",
            "dpop_proof",
        ] {
            assert!(
                SyncNotification::from_cbor(&extended(&bytes, key, Value::Null)).is_err(),
                "{key}"
            );
        }
    }
    for key in ["organization", "vault", "view_revision", "organization_view_changed"] {
        assert!(
            SyncNotification::from_cbor(&extended(
                &SyncNotification::MembershipsChanged.to_cbor().unwrap(),
                key,
                Value::Null
            ))
            .is_err()
        );
    }
    for key in ["organization", "view_revision", "organization_view_changed", "memberships_changed"]
    {
        assert!(
            SyncNotification::from_cbor(&extended(
                &SyncNotification::DeviceRevoked.to_cbor().unwrap(),
                key,
                Value::Null
            ))
            .is_err()
        );
        assert!(
            SyncNotificationContext::from_cbor(&encode(vec![
                ("htm", Value::Text("GET".into())),
                (key, Value::Null)
            ]))
            .is_err()
        );
        assert!(
            SyncNotificationReady::from_cbor(&encode(vec![
                ("authenticated", Value::Bool(true)),
                (key, Value::Null)
            ]))
            .is_err()
        );
    }
    assert!(
        SyncNotification::from_cbor(&encode(vec![("memberships_changed", Value::Bool(false))]))
            .is_err()
    );
    assert!(
        SyncNotification::OrganizationViewChanged {
            organization: id(1),
            vault: id(2),
            view_revision: 0
        }
        .to_cbor()
        .is_err()
    );
}

#[test]
fn independent_organization_view_vectors_use_public_codecs() {
    use scoplen_api::sync::SyncCodecError;
    fn wire(kind: &str, bytes: &[u8]) -> Result<Vec<u8>, SyncCodecError> {
        match kind {
            "sync.organization.view" => SyncOrganizationViewResponse::from_cbor(bytes)?.to_cbor(),
            "sync.organization.ack_request" => {
                SyncOrganizationAckRequest::from_cbor(bytes)?.to_cbor()
            }
            "sync.organization.ack_response" => {
                SyncOrganizationAckResponse::from_cbor(bytes)?.to_cbor()
            }
            "sync.organization.session" => SyncSessionResponse::from_cbor(bytes)?.to_cbor(),
            "sync.organization.notification" => SyncNotification::from_cbor(bytes)?.to_cbor(),
            _ => panic!("unexpected vector kind {kind}"),
        }
    }
    let document = scoplen_test_vectors::VectorDocument::parse_str(include_str!(
        "../../../vectors/organization-view.json"
    ))
    .unwrap();
    assert_eq!(document.vectors.len(), 65);
    for vector in document.vectors {
        if vector.kind == "sync.organization.problem" {
            let input = hex(&vector.input);
            let problem = scoplen_api::ProblemDetails::from_cbor(&input).unwrap();
            assert_eq!(problem.status, 409);
            assert_eq!(problem.code.as_str(), "sync.view_changed");
            assert!(!problem.changed && problem.retryable);
            assert_eq!(problem.to_cbor().unwrap(), hex(&vector.expected));
            assert_eq!(
                serde_json::from_slice::<scoplen_api::ProblemDetails>(
                    &serde_json::to_vec(&problem).unwrap()
                )
                .unwrap(),
                problem
            );
        } else if vector.kind == "sync.organization.query" {
            let result = SyncOrganizationViewQuery::from_query(&vector.input)
                .and_then(|query| query.to_query());
            if vector.expected == "rejected" {
                assert!(result.is_err(), "{}", vector.id);
            } else {
                assert_eq!(result.unwrap(), vector.expected, "{}", vector.id);
            }
        } else {
            let input = hex(&vector.input);
            let result = wire(&vector.kind, &input);
            if vector.expected == "rejected" {
                assert!(result.is_err(), "{}", vector.id);
            } else {
                let encoded = result.unwrap();
                assert_eq!(encoded, hex(&vector.expected), "{}", vector.id);
                assert_eq!(wire(&vector.kind, &encoded).unwrap(), encoded);
            }
        }
    }
}

fn hex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
