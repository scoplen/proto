// SPDX-License-Identifier: Apache-2.0
#![no_main]

use libfuzzer_sys::fuzz_target;
use scoplen_api::sync::{
    SyncNotification, SyncNotificationAuth, SyncNotificationContext, SyncNotificationReady,
};

fuzz_target!(|bytes: &[u8]| {
    if let Ok(context) = SyncNotificationContext::from_cbor(bytes) {
        let encoded = context.to_cbor().expect("validated context encodes");
        assert_eq!(SyncNotificationContext::from_cbor(&encoded), Ok(context));
    }
    if let Ok(auth) = SyncNotificationAuth::from_cbor(bytes) {
        let encoded = auth.to_cbor().expect("validated authentication encodes");
        assert_eq!(SyncNotificationAuth::from_cbor(&encoded), Ok(auth));
    }
    if let Ok(ready) = SyncNotificationReady::from_cbor(bytes) {
        let encoded = ready.to_cbor().expect("validated acknowledgement encodes");
        assert_eq!(SyncNotificationReady::from_cbor(&encoded), Ok(ready));
    }
    if let Ok(notification) = SyncNotification::from_cbor(bytes) {
        let encoded = notification.to_cbor().expect("validated event encodes");
        assert_eq!(SyncNotification::from_cbor(&encoded), Ok(notification));
    }
});
