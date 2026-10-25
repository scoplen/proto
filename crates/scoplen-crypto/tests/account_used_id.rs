// SPDX-License-Identifier: Apache-2.0
use scoplen_crypto::account_used_id_digest;
use scoplen_test_vectors::VectorDocument;
use uuid::Uuid;

#[test]
fn independent_account_id_digests_bind_exact_raw_uuid_without_a_time_window() {
    let document =
        VectorDocument::parse_str(include_str!("../../../vectors/account-used-id.json")).unwrap();
    let mut digests = std::collections::BTreeSet::new();
    let mut rejected = 0;
    for vector in document.vectors {
        assert_eq!(vector.kind, "account.used-id.digest");
        let id = Uuid::parse_str(&vector.input).unwrap();
        let digest = account_used_id_digest(id);
        if vector.expected == "rejected" {
            rejected += 1;
            assert!(digest.is_err(), "{}", vector.id);
        } else {
            let digest = digest.unwrap();
            let expected: Vec<_> = vector
                .expected
                .as_bytes()
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                .collect();
            assert_eq!(digest.as_slice(), expected, "{}", vector.id);
            assert_eq!(account_used_id_digest(id).unwrap(), digest);
            assert!(digests.insert(digest), "distinct Account ids must have distinct fixtures");
        }
    }
    assert_eq!(digests.len(), 3);
    assert_eq!(rejected, 4);
}
