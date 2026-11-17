// SPDX-License-Identifier: Apache-2.0
use scoplen_api::inventory_import::{
    InventoryImportRequest, InventoryImportRow, InventoryOpenSshCandidate,
    inventory_openssh_preview, parse_inventory_openssh,
};
use scoplen_test_vectors::VectorDocument;
use serde_json::Value;
use uuid::Uuid;

fn input(kind: &str, source: &str) -> Vec<u8> {
    if kind == "inventory.import.openssh.bound" {
        let recipe: Value = serde_json::from_str(source).unwrap();
        let mut input = vec![
            u8::try_from(recipe["fill"].as_u64().unwrap_or(120)).unwrap();
            usize::try_from(recipe["bytes"].as_u64().unwrap()).unwrap()
        ];
        let source = recipe["source"].as_str().unwrap().as_bytes();
        input[..source.len()].copy_from_slice(source);
        input
    } else {
        source
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }
}

#[test]
fn independent_vectors_exercise_the_public_parser_preview_and_redacting_debug() {
    let document =
        VectorDocument::parse_str(include_str!("../../../vectors/openssh-inventory-import.json"))
            .unwrap();
    assert!(document.vectors.len() > 130);
    for vector in document.vectors {
        let input = input(&vector.kind, &vector.input);
        let actual = inventory_openssh_preview(&input).unwrap_or_else(|error| error.to_json());
        assert_eq!(actual, vector.expected, "{}", vector.id);
        if let Ok(candidates) = parse_inventory_openssh(&input) {
            let parsed: Value = serde_json::from_str(&actual).unwrap();
            assert_eq!(serde_json::to_value(&candidates).unwrap(), parsed["candidates"]);
            for candidate in &candidates {
                if let InventoryOpenSshCandidate::Ready { fields, .. } = candidate {
                    fields.validate().unwrap();
                    assert_eq!(fields.login_name, None);
                    assert_eq!(format!("{fields:?}"), "InventoryImportFields { .. }");
                }
            }
        }
    }
}

#[test]
fn explicit_ready_selection_keeps_order_and_uses_unchanged_d151_atomic_request() {
    let candidates = parse_inventory_openssh(
        b"Host First\nUser op\nHost blocked\nProxyJump none\nHost Last\nUser OP",
    )
    .unwrap();
    assert_eq!(candidates.len(), 3);
    let mut rows = Vec::new();
    for (index, candidate) in candidates.into_iter().enumerate() {
        if let InventoryOpenSshCandidate::Ready { candidate, fields } = candidate {
            assert_eq!(candidate, index + 1);
            rows.push(InventoryImportRow {
                host_id: Uuid::from_u128(
                    0x019b_dad6_b800_7000_8000_0000_0000_0010 + index as u128 * 2,
                ),
                access_profile_id: Uuid::from_u128(
                    0x019b_dad6_b800_7000_8000_0000_0000_0011 + index as u128 * 2,
                ),
                fields,
            });
        }
    }
    let request = InventoryImportRequest { rows };
    assert_eq!(
        request.rows.iter().map(|row| row.fields.name.as_str()).collect::<Vec<_>>(),
        ["First", "Last"]
    );
    for row in &request.rows {
        let (host, login) = row.inventory_creates().unwrap();
        assert_eq!(host.id, row.host_id);
        assert_eq!(login.id, row.access_profile_id);
    }
    let encoded = request.to_json().unwrap();
    assert_eq!(InventoryImportRequest::from_json(&encoded).unwrap(), request);
    let json: Value = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(json["rows"][0]["name"], "First");
    assert!(json["rows"][0].get("status").is_none());
    assert!(json["rows"][0].get("login_name").is_none());
}

#[test]
fn diagnostics_and_all_debug_surfaces_redact_source_path_values_and_ready_rows() {
    let source = b"Host PRIVATE-ALIAS\nUser PRIVATE-USER\nHostName PRIVATE-HOST\nHost blocked\nPRIVATE-KEYWORD /example/import-option";
    let candidates = parse_inventory_openssh(source).unwrap();
    let debug = format!("{candidates:?}");
    assert!(!debug.contains("PRIVATE"));
    let InventoryOpenSshCandidate::Blocked { diagnostic } = &candidates[1] else {
        panic!("second candidate must be blocked");
    };
    assert!(!serde_json::to_string(diagnostic).unwrap().contains("PRIVATE"));
    let error =
        parse_inventory_openssh(b"Host PRIVATE\nInclude /example/import-option").unwrap_err();
    for diagnostic in [format!("{error:?}"), error.to_string(), error.to_json()] {
        assert!(!diagnostic.contains("PRIVATE"));
        assert!(!diagnostic.contains("/example/import-option"));
    }
    assert!(inventory_openssh_preview(source).unwrap().contains("PRIVATE-ALIAS"));
}

#[test]
fn oversized_aliases_still_deduplicate_by_decoded_bytes_before_field_validation() {
    let alias = "a".repeat(16385);
    let source = format!("Host {alias} \"{alias}\"\nUser op");
    let candidates = parse_inventory_openssh(source.as_bytes()).unwrap();
    assert_eq!(candidates.len(), 1);
    assert!(matches!(&candidates[0], InventoryOpenSshCandidate::Blocked { .. }));
}
