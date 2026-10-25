// SPDX-License-Identifier: Apache-2.0
#![no_main]

use libfuzzer_sys::fuzz_target;
use scoplen_api::ProblemDetails;
use scoplen_api::account_admission::{
    AccountBootstrapSnapshot, AccountCommittedConfirmation, AccountDeviceAdmissionPayload,
    AccountDeviceAdmissionRequest, AccountPasswordLoginRequest, AccountPasswordLoginResponse,
    AccountPasswordOptionsRequest, AccountPasswordOptionsResponse, AccountRegistrationPayload,
    AccountRegistrationRequest, AccountRequestChallengeRequest, AccountRequestChallengeResponse,
};
use scoplen_api::account_devices::AccountDeviceStatements;
use scoplen_api::account_profile::AccountProfile;
use scoplen_api::auth::{
    AuthChallengeRequest, AuthChallengeResponse, AuthDeviceRequest, AuthJwks, AuthRefreshRequest,
    AuthTokenResponse, BrowserAuthRefreshRequest, BrowserAuthTokenResponse,
};
use scoplen_api::certificate::{CertificateIssuanceRequest, CertificateIssuanceResponse};
use scoplen_api::gateway_ticket::{
    GatewayTicketCodecError, GatewayTicketRequest, GatewayTicketResponse,
};
use scoplen_api::operator_auth::{
    OperatorLoginFinishRequest, OperatorLoginOptionsRequest, OperatorLoginOptionsResponse,
    OperatorLogoutRequest, OperatorLogoutResponse, OperatorSetupFinishRequest,
    OperatorSetupFinishResponse, OperatorSetupOptionsRequest, OperatorSetupOptionsResponse,
};

macro_rules! round_trip {
    ($message:ty, $input:expr) => {
        if let Ok(message) = <$message>::from_json($input) {
            let encoded = message.to_json().expect("validated JSON message encodes");
            assert_eq!(<$message>::from_json(&encoded), Ok(message));
            let decoded = <$message>::from_json(&encoded).expect("canonical JSON decodes");
            assert_eq!(decoded.to_json().expect("canonical JSON encodes"), encoded);
        }
    };
}

fuzz_target!(|bytes: &[u8]| {
    if let Ok(problem) = serde_json::from_slice::<ProblemDetails>(bytes) {
        let encoded = serde_json::to_vec(&problem).expect("validated problem encodes");
        assert_eq!(
            serde_json::from_slice::<ProblemDetails>(&encoded).expect("canonical problem decodes"),
            problem,
        );
    }
    round_trip!(AccountProfile, bytes);
    round_trip!(AccountDeviceStatements, bytes);
    round_trip!(AccountRequestChallengeRequest, bytes);
    round_trip!(AccountRequestChallengeResponse, bytes);
    round_trip!(AccountPasswordOptionsRequest, bytes);
    round_trip!(AccountPasswordOptionsResponse, bytes);
    round_trip!(AccountPasswordLoginResponse, bytes);
    round_trip!(AccountRegistrationRequest, bytes);
    round_trip!(AccountDeviceAdmissionRequest, bytes);
    round_trip!(AccountCommittedConfirmation, bytes);
    if let Ok(request) = AccountPasswordLoginRequest::from_json(bytes) {
        let encoded = request.to_json().expect("validated secret request encodes");
        assert_eq!(AccountPasswordLoginRequest::from_json(encoded.as_bytes()), Ok(request));
    }
    if let Ok(value) = AccountRegistrationPayload::from_cbor(bytes) {
        assert_eq!(value.to_cbor().expect("validated protected registration"), bytes);
    }
    if let Ok(value) = AccountDeviceAdmissionPayload::from_cbor(bytes) {
        assert_eq!(value.to_cbor().expect("validated protected admission"), bytes);
    }
    if let Ok(value) = AccountBootstrapSnapshot::from_cbor(bytes) {
        assert_eq!(value.to_cbor().expect("validated complete snapshot"), bytes);
    }
    round_trip!(AuthJwks, bytes);
    round_trip!(OperatorSetupOptionsRequest, bytes);
    round_trip!(OperatorSetupFinishRequest, bytes);
    round_trip!(OperatorLoginOptionsRequest, bytes);
    round_trip!(OperatorLoginFinishRequest, bytes);
    round_trip!(OperatorSetupOptionsResponse, bytes);
    round_trip!(OperatorLoginOptionsResponse, bytes);
    round_trip!(OperatorSetupFinishResponse, bytes);
    round_trip!(OperatorLogoutRequest, bytes);
    round_trip!(OperatorLogoutResponse, bytes);
    round_trip!(CertificateIssuanceRequest, bytes);
    round_trip!(CertificateIssuanceResponse, bytes);
    round_trip!(GatewayTicketRequest, bytes);
    round_trip!(GatewayTicketResponse, bytes);
    assert_eq!(
        GatewayTicketRequest::from_http_json(bytes, true),
        Err(GatewayTicketCodecError::IdempotencyKey)
    );
    assert_eq!(
        GatewayTicketRequest::from_http_json(bytes, false),
        GatewayTicketRequest::from_json(bytes)
    );

    if let Ok(text) = std::str::from_utf8(bytes) {
        round_trip!(AuthChallengeRequest, text);
        round_trip!(AuthChallengeResponse, text);
        round_trip!(AuthDeviceRequest, text);
        round_trip!(AuthRefreshRequest, text);
        round_trip!(AuthTokenResponse, text);
        round_trip!(BrowserAuthTokenResponse, text);
        if let Ok(request) = BrowserAuthRefreshRequest::from_json(text) {
            assert_eq!(BrowserAuthRefreshRequest::from_json(request.to_json()), Ok(request));
        }
    }
});
