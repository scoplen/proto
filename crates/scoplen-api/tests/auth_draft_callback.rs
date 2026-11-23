// SPDX-License-Identifier: Apache-2.0

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use scoplen_api::auth_connection_draft::callback::{
    Callback, CallbackResult, InvalidCallback, IssuerIdentification, callback_path,
};

const ISSUER: &str = "https://Issuer.example:443/Case%2fPath/";
const OTHER: &str = "https://issuer.example/Case%2fPath/";
const ENCODED_ISSUER: &str = "https%3A%2F%2FIssuer.example%3A443%2FCase%252fPath%2F";

fn parse<'a>(path: &'a str, query: &str) -> Result<Callback<'a>, InvalidCallback> {
    let binding = URL_SAFE_NO_PAD.encode([42; 32]);
    Callback::parse("GET", path, query, [binding].into_iter())
}

fn verify(
    query: &str,
    identification: IssuerIdentification,
) -> Result<CallbackResult, InvalidCallback> {
    parse(&callback_path(ISSUER)?, query)?.bind_issuer(ISSUER, identification)
}

#[test]
fn callback_path_preserves_exact_issuer_spelling() {
    let expected = concat!(
        "/api/v1/auth/enterprise/oidc/",
        "ff0d9b41c91b24d0b9f9a8bd2c252aad61ca89761016040c1aa68e0381197328",
        "/callback"
    );
    assert_eq!(callback_path(ISSUER).unwrap(), expected);
    assert_ne!(callback_path(OTHER).unwrap(), expected);
    assert_ne!(callback_path(ISSUER.trim_end_matches('/')).unwrap(), expected);
    assert_eq!(callback_path("http://issuer.example"), Err(InvalidCallback));
}

#[test]
fn accepts_bound_shapes_and_redacts_provider_values() {
    use IssuerIdentification::{ExclusiveCallback, ResponseParameter};
    let state = URL_SAFE_NO_PAD.encode([17; 32]);
    let query =
        format!("state={state}&iss={ENCODED_ISSUER}&code=test%2Bopaque+code&extension=value");
    let path = callback_path(ISSUER).unwrap();
    let callback = parse(&path, &query).unwrap();
    assert_eq!(callback.state.as_bytes(), &[17; 32]);
    assert_eq!(callback.browser_binding.as_bytes(), &[42; 32]);
    let debug = format!("{callback:?}");
    assert!(!debug.contains("opaque") && !debug.contains(&state));
    let CallbackResult::Code(code) = callback.bind_issuer(ISSUER, ResponseParameter).unwrap()
    else {
        panic!("expected a code")
    };
    assert_eq!(code.as_bytes(), b"test+opaque code");

    let query = format!("state={state}&error=access_denied&error_description=provider+detail");
    assert_eq!(verify(&query, ExclusiveCallback).unwrap(), CallbackResult::Denied);
    assert_eq!(verify(&query, ResponseParameter), Err(InvalidCallback));
    let denial = parse(&path, &format!("{query}&iss={ENCODED_ISSUER}")).unwrap();
    assert!(!format!("{denial:?}").contains("provider"));
    assert_eq!(denial.bind_issuer(ISSUER, ResponseParameter), Ok(CallbackResult::Denied));
}

#[test]
fn rejects_ambiguous_and_out_of_bounds_callbacks() {
    use IssuerIdentification::{ExclusiveCallback, ResponseParameter};
    let state = URL_SAFE_NO_PAD.encode([17; 32]);
    for query in [
        format!("state={state}&code="),
        format!("state={state}&code=one&code=two"),
        format!("state={state}&%73tate={state}&code=one"),
        format!("state={state}&code=one&error=access_denied"),
        format!("state={state}&code=one&iss={ENCODED_ISSUER}"),
        format!("state={state}&code=one&extension=%"),
        format!("state={state}&code=one&extension=%FF"),
        format!("state={state}&code=one&extension"),
        format!("state={state}=&code=one"),
        format!("state={}B&code=one", &state[..42]),
        format!("state={state}&code={}", "a".repeat(4_097)),
        format!("state={state}&code=one&extension={}", "a".repeat(8_192)),
    ] {
        assert_eq!(verify(&query, ExclusiveCallback), Err(InvalidCallback));
    }
    for value in [OTHER.to_owned(), format!("{ENCODED_ISSUER}&%69ss={ENCODED_ISSUER}")] {
        let query = format!("state={state}&code=one&iss={value}");
        assert_eq!(verify(&query, ResponseParameter), Err(InvalidCallback));
    }
    let max_code = format!("state={state}&code={}", "a".repeat(4_096));
    assert!(verify(&max_code, ExclusiveCallback).is_ok());

    let query = format!("state={state}&code=one");
    let binding = URL_SAFE_NO_PAD.encode([42; 32]);
    let path = callback_path(ISSUER).unwrap();
    let other_path = callback_path(OTHER).unwrap();
    let wrong_path = parse(&other_path, &query).unwrap();
    assert_eq!(wrong_path.bind_issuer(ISSUER, ExclusiveCallback), Err(InvalidCallback));
    for (method, path, cookies) in [
        ("POST", path.as_str(), vec![binding.as_str()]),
        ("GET", "/api/v1/auth/enterprise/oidc/elsewhere/callback", vec![binding.as_str()]),
        ("GET", path.as_str(), vec![]),
        ("GET", path.as_str(), vec!["short"]),
        ("GET", path.as_str(), vec![binding.as_str(), binding.as_str()]),
    ] {
        assert_eq!(
            Callback::parse(method, path, &query, cookies.into_iter()),
            Err(InvalidCallback)
        );
    }
}
