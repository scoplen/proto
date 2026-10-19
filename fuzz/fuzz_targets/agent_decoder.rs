// SPDX-License-Identifier: Apache-2.0
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    if let Ok(message) = scoplen_ssh::AgentMessage::decode_frame(bytes) {
        let encoded = message.encode_frame().expect("decoded message re-encodes");
        assert_eq!(scoplen_ssh::AgentMessage::decode_frame(&encoded), Ok(message));
    }
});
