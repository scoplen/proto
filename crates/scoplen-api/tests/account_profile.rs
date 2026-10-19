// SPDX-License-Identifier: Apache-2.0

use scoplen_api::account_profile::{
    AccountProfile, AccountProfileCodecError as Error, MAX_ACCOUNT_EMAIL_BYTES,
    MAX_ACCOUNT_PROFILE_BYTES,
};
use scoplen_test_vectors::VectorDocument;
use serde_json::Value;

fn vectors() -> VectorDocument {
    VectorDocument::from_path(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors/account-profile.json"),
    )
    .expect("account profile vectors")
}

fn valid_body() -> String {
    vectors()
        .vectors
        .into_iter()
        .find(|vector| vector.id == "account-profile-null-v1")
        .expect("null vector")
        .expected
}

#[test]
fn published_profiles_and_failures_match_public_codec() {
    let document = vectors();
    assert_eq!(document.vectors.len(), 9);
    for vector in document.vectors {
        match vector.kind.as_str() {
            "account.profile.response_json" => {
                let profile = AccountProfile::from_json(vector.input.as_bytes()).expect(&vector.id);
                assert_eq!(profile.to_json().expect(&vector.id), vector.expected.as_bytes());
                assert_eq!(AccountProfile::from_json(vector.expected.as_bytes()), Ok(profile));
            }
            "account.profile.response_invalid" => {
                let error =
                    AccountProfile::from_json(vector.input.as_bytes()).expect_err(&vector.id);
                let actual = match error {
                    Error::InvalidField(field) => format!("InvalidField({field})"),
                    Error::InvalidJson => "InvalidJson".to_owned(),
                    other => panic!("unexpected vector error: {other:?}"),
                };
                assert_eq!(actual, vector.expected, "{}", vector.id);
            }
            "account.profile.response_budget" => {
                let recipe: Value = serde_json::from_str(&vector.input).expect("budget recipe");
                assert_eq!(recipe["base"], "account-profile-null-v1");
                assert_eq!(recipe["extension"], "x");
                let total = usize::try_from(recipe["total_bytes"].as_u64().expect("total"))
                    .expect("portable body length");
                let base = valid_body();
                let prefix = format!("{},\"x\":\"", &base[..base.len() - 1]);
                let body = format!("{prefix}{}\"}}", "a".repeat(total - prefix.len() - 2));
                assert_eq!(body.len(), total);
                if total <= MAX_ACCOUNT_PROFILE_BYTES {
                    assert_eq!(
                        AccountProfile::from_json(body.as_bytes()).expect(&vector.id).email,
                        None
                    );
                } else {
                    assert_eq!(
                        AccountProfile::from_json(body.as_bytes()),
                        Err(Error::ResponseTooLarge)
                    );
                }
                assert_eq!(
                    vector.expected,
                    format!(
                        "{}:{total}",
                        if total <= MAX_ACCOUNT_PROFILE_BYTES { "accept" } else { "reject" }
                    )
                );
            }
            other => panic!("unexpected vector kind {other}"),
        }
    }
}

#[test]
fn email_is_required_and_preserved_without_normalization() {
    let source = valid_body();
    for invalid in [
        source.replace("\"email\":null", ""),
        source.replace("\"email\":null", "\"email\":true"),
        source.replace("\"email\":null", "\"email\":\"\""),
        source.replace("\"email\":null", "\"email\":\"a\\tb\""),
        source.replace("\"email\":null", "\"email\":\"a b\""),
        source.replace("\"email\":null", "\"email\":\"a　b\""),
        source.replace(
            "\"email\":null",
            &format!("\"email\":\"{}\"", "a".repeat(MAX_ACCOUNT_EMAIL_BYTES + 1)),
        ),
    ] {
        assert_eq!(
            AccountProfile::from_json(invalid.as_bytes()),
            Err(Error::InvalidField("data.email"))
        );
    }
    let email = format!("{}a@Example.test", "é".repeat(153));
    assert_eq!(email.len(), MAX_ACCOUNT_EMAIL_BYTES);
    let body = source.replace(
        "\"email\":null",
        &format!("\"email\":{}", serde_json::to_string(&email).unwrap()),
    );
    let decoded = AccountProfile::from_json(body.as_bytes()).expect("320-byte Unicode email");
    assert_eq!(decoded.email.as_deref(), Some(email.as_str()));
    assert_eq!(AccountProfile::from_json(&decoded.to_json().unwrap()), Ok(decoded));
}

#[test]
fn metadata_http_extensions_and_mutation_fail_closed() {
    let source = valid_body();
    let profile = AccountProfile::from_http_json(
        source.as_bytes(),
        Some("\"1\""),
        Some("no-store"),
        Some("no-cache"),
    )
    .expect("HTTP profile");
    for (etag, cache, pragma) in [
        (None, Some("no-store"), Some("no-cache")),
        (Some("W/\"1\""), Some("no-store"), Some("no-cache")),
        (Some("\"1\""), None, Some("no-cache")),
        (Some("\"1\""), Some("public"), Some("no-cache")),
        (Some("\"1\""), Some("no-store"), None),
    ] {
        assert_eq!(
            AccountProfile::from_http_json(source.as_bytes(), etag, cache, pragma),
            Err(Error::HttpMetadata)
        );
    }
    for body in [
        source.replace("\"etag\":\"\\\"1\\\"\"", "\"etag\":\"W/\\\"1\\\"\""),
        source.replace("2026-01-20T00:00:00Z", "2026-02-30T00:00:00Z"),
        source.replace(
            "019bdad6-b800-7000-8000-000000000001",
            "019BDAD6-B800-7000-8000-000000000001",
        ),
    ] {
        assert!(AccountProfile::from_json(body.as_bytes()).is_err());
    }
    let nested_duplicate =
        format!("{},\"ignored\":[{{\"x\":1,\"x\":2}}]}}", &source[..source.len() - 1]);
    assert_eq!(AccountProfile::from_json(nested_duplicate.as_bytes()), Err(Error::InvalidJson));
    let mut changed = profile.clone();
    changed.email = Some("bad address".into());
    assert_eq!(changed.to_json(), Err(Error::InvalidField("data.email")));
    assert!(!format!("{changed:?}").contains("bad address"));
    assert!(!format!("{:?}", changed.to_json().unwrap_err()).contains("bad address"));
}
