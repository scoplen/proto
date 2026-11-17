// SPDX-License-Identifier: Apache-2.0
use scoplen_test_vectors::VectorDocument;
use serde_json::Value;

#[test]
fn native_browser_facade_matches_every_independent_openssh_answer() {
    let document =
        VectorDocument::parse_str(include_str!("../../../vectors/openssh-inventory-import.json"))
            .unwrap();
    for vector in document.vectors {
        let input = if vector.kind == "inventory.import.openssh.bound" {
            let recipe: Value = serde_json::from_str(&vector.input).unwrap();
            let mut input = vec![
                u8::try_from(recipe["fill"].as_u64().unwrap_or(120)).unwrap();
                usize::try_from(recipe["bytes"].as_u64().unwrap()).unwrap()
            ];
            let source = recipe["source"].as_str().unwrap().as_bytes();
            input[..source.len()].copy_from_slice(source);
            input
        } else {
            vector
                .input
                .as_bytes()
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                .collect()
        };
        assert_eq!(
            scoplen_browser::inventory_openssh(&input).unwrap_or_else(|error| error.to_json()),
            vector.expected,
            "{}",
            vector.id
        );
    }
}
