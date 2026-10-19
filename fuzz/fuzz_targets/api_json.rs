// SPDX-License-Identifier: Apache-2.0
#![no_main]

use libfuzzer_sys::fuzz_target;
use scoplen_api::auth::{
    AuthChallengeRequest, AuthChallengeResponse, AuthDeviceRequest, AuthRefreshRequest,
    AuthTokenResponse, BrowserAuthRefreshRequest, BrowserAuthTokenResponse,
};
use scoplen_api::gateway_ticket::{
    GatewayTicketCodecError, GatewayTicketRequest, GatewayTicketResponse,
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
