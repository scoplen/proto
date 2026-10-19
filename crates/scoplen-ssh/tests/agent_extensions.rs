// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::VecDeque,
    sync::atomic::{AtomicUsize, Ordering},
};

use scoplen_ssh::{
    AgentChannel, AgentClient, AgentError, AgentForwardingAdapter, AgentForwardingAuthorizer,
    AgentForwardingPolicy, AgentIdentity, AgentKeyStore, AgentMessage, AgentServer,
    MAX_AGENT_EXTENSION_DATA, MAX_AGENT_EXTENSION_NAME,
};

fn string(output: &mut Vec<u8>, bytes: &[u8]) {
    output.extend_from_slice(&u32::try_from(bytes.len()).expect("test string").to_be_bytes());
    output.extend_from_slice(bytes);
}

fn frame(payload: &[u8]) -> Vec<u8> {
    let mut result = u32::try_from(payload.len()).expect("test frame").to_be_bytes().to_vec();
    result.extend_from_slice(payload);
    result
}

fn extension_frame(code: u8, name: &[u8], contents: &[u8]) -> Vec<u8> {
    let mut payload = vec![code];
    string(&mut payload, name);
    payload.extend_from_slice(contents);
    frame(&payload)
}

fn session_bind_contents() -> Vec<u8> {
    let mut contents = Vec::new();
    string(&mut contents, b"synthetic-host-key");
    string(&mut contents, b"synthetic-session-id");
    string(&mut contents, b"synthetic-signature");
    contents.push(1);
    contents
}

fn hex(input: &str) -> Vec<u8> {
    assert_eq!(input.len() % 2, 0);
    input
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).expect("hex text"), 16).expect("hex byte")
        })
        .collect()
}

#[test]
fn portable_extension_wire_vectors_round_trip_or_reject() {
    let document = scoplen_test_vectors::VectorDocument::parse_str(include_str!(
        "../../../vectors/ssh-agent-extensions.json"
    ))
    .expect("portable vectors");
    assert_eq!(document.vectors.len(), 9);
    for vector in document.vectors {
        let bytes = hex(&vector.input);
        match vector.kind.as_str() {
            "ssh.agent.extension.valid" => {
                let decoded = AgentMessage::decode_frame(&bytes).expect(&vector.id);
                assert_eq!(
                    decoded.encode_frame().expect(&vector.id),
                    hex(&vector.expected),
                    "{}",
                    vector.id
                );
            }
            "ssh.agent.extension.invalid" => {
                assert_eq!(vector.expected, "reject");
                assert!(AgentMessage::decode_frame(&bytes).is_err(), "{}", vector.id);
            }
            other => panic!("unknown vector kind: {other}"),
        }
    }
}

#[test]
fn extension_contents_are_the_raw_remainder_in_both_directions() {
    for (name, contents) in [
        (b"query".as_slice(), Vec::new()),
        (b"session-bind@openssh.com", session_bind_contents()),
        (b"vendor@example.com", vec![0, 255, 0, 1, 2]),
    ] {
        for (code, message) in [
            (
                27,
                AgentMessage::ExtensionRequest { name: name.to_vec(), contents: contents.clone() },
            ),
            (
                29,
                AgentMessage::ExtensionResponse { name: name.to_vec(), contents: contents.clone() },
            ),
        ] {
            let bytes = extension_frame(code, name, &contents);
            assert_eq!(AgentMessage::decode_frame(&bytes), Ok(message.clone()));
            assert_eq!(message.encode_frame(), Ok(bytes));
        }
    }
}

#[test]
fn extension_limits_and_utf8_are_checked_in_both_directions() {
    for code in [27, 29] {
        let name = vec![b'n'; MAX_AGENT_EXTENSION_NAME];
        let contents = vec![0; MAX_AGENT_EXTENSION_DATA];
        let bytes = extension_frame(code, &name, &contents);
        assert_eq!(
            AgentMessage::decode_frame(&bytes).expect("exact bounds").encode_frame(),
            Ok(bytes)
        );
        for (name, contents) in [
            (Vec::new(), Vec::new()),
            (vec![255], Vec::new()),
            (vec![b'n'; MAX_AGENT_EXTENSION_NAME + 1], Vec::new()),
            (b"query".to_vec(), vec![0; MAX_AGENT_EXTENSION_DATA + 1]),
        ] {
            let message = if code == 27 {
                AgentMessage::ExtensionRequest { name: name.clone(), contents: contents.clone() }
            } else {
                AgentMessage::ExtensionResponse { name: name.clone(), contents: contents.clone() }
            };
            assert!(message.encode_frame().is_err());
            assert!(AgentMessage::decode_frame(&extension_frame(code, &name, &contents)).is_err());
        }
        let bytes = extension_frame(code, "example-\u{03b1}@example.com".as_bytes(), b"");
        assert!(AgentMessage::decode_frame(&bytes).is_ok());
        assert!(AgentMessage::decode_frame(&frame(&[code, 0, 0, 0, 5, b'q'])).is_err());
    }
    assert_eq!(
        AgentMessage::decode_frame(&frame(&[6, 0])),
        Err(AgentError::MalformedFrame("success payload"))
    );
}

struct Replies {
    frames: VecDeque<Vec<u8>>,
    requests: Vec<Vec<u8>>,
}

impl AgentChannel for Replies {
    fn exchange(&mut self, request: &[u8]) -> Result<Vec<u8>, AgentError> {
        self.requests.push(request.to_vec());
        Ok(self.frames.pop_front().expect("test response"))
    }
}

#[test]
fn extension_client_binds_name_and_accepts_bare_success_and_refusal() {
    let responses = [
        extension_frame(29, b"query", b"opaque"),
        frame(&[6]),
        extension_frame(29, b"other", b"untrusted"),
        frame(&[5]),
        frame(&[28]),
        extension_frame(29, b"query", b"healthy"),
    ];
    let mut client = AgentClient::new(Replies { frames: responses.into(), requests: Vec::new() });
    assert_eq!(client.extension(b"query", b""), Ok(b"opaque".to_vec()));
    assert_eq!(client.extension(b"query", b""), Ok(Vec::new()));
    assert_eq!(client.extension(b"query", b""), Err(AgentError::UnexpectedResponse));
    assert_eq!(client.extension(b"query", b""), Err(AgentError::AgentFailure));
    assert_eq!(client.extension(b"query", b""), Err(AgentError::AgentFailure));
    assert_eq!(client.extension(b"query", b""), Ok(b"healthy".to_vec()));
    assert_eq!(client.extension(&[255], b""), Err(AgentError::MalformedFrame("extension name")));
    let channel = client.into_inner();
    assert_eq!(channel.requests, vec![extension_frame(27, b"query", b""); 6]);
}

#[derive(Default)]
struct Store {
    extensions: AtomicUsize,
    signs: AtomicUsize,
}

impl AgentKeyStore for &Store {
    fn identities(&self) -> Result<Vec<AgentIdentity>, AgentError> {
        Ok(vec![AgentIdentity::new(b"synthetic-key", b"")?])
    }

    fn sign(&self, key: &[u8], data: &[u8], flags: u32) -> Result<Vec<u8>, AgentError> {
        assert_eq!((key, data, flags), (b"synthetic-key".as_slice(), b"payload".as_slice(), 0));
        self.signs.fetch_add(1, Ordering::SeqCst);
        Ok(b"synthetic-signature".to_vec())
    }

    fn extension(&self, name: &[u8], contents: &[u8]) -> Result<Vec<u8>, AgentError> {
        self.extensions.fetch_add(1, Ordering::SeqCst);
        match name {
            b"echo@example.com" => Ok(contents.to_vec()),
            b"oversized@example.com" => Ok(vec![0; MAX_AGENT_EXTENSION_DATA + 1]),
            b"failed@example.com" => Err(AgentError::AgentFailure),
            _ => Err(AgentError::UnsupportedExtension),
        }
    }
}

#[test]
fn extension_server_echoes_name_and_distinguishes_unsupported_from_failed() {
    let store = Store::default();
    let server = AgentServer::new(&store);
    for (name, expected) in [
        (b"echo@example.com".as_slice(), extension_frame(29, b"echo@example.com", b"raw\0bytes")),
        (b"failed@example.com", frame(&[28])),
        (b"oversized@example.com", frame(&[28])),
        (b"unknown@example.com", frame(&[5])),
    ] {
        assert_eq!(server.dispatch_frame(&extension_frame(27, name, b"raw\0bytes")), Ok(expected));
    }
    assert_eq!(store.extensions.load(Ordering::SeqCst), 4);
}

struct NoExtensions;

impl AgentKeyStore for NoExtensions {
    fn identities(&self) -> Result<Vec<AgentIdentity>, AgentError> {
        Ok(Vec::new())
    }

    fn sign(&self, _: &[u8], _: &[u8], _: u32) -> Result<Vec<u8>, AgentError> {
        Err(AgentError::AgentFailure)
    }
}

#[test]
fn default_store_reports_extensions_as_unsupported() {
    let server = AgentServer::new(NoExtensions);
    assert_eq!(server.dispatch_frame(&extension_frame(27, b"query", b"")), Ok(frame(&[5])));
}

#[test]
fn forwarded_session_bind_refusal_preserves_queries_and_authorized_signing() {
    let store = Store::default();
    let approvals = AtomicUsize::new(0);
    let policy = AgentForwardingPolicy::enabled(Approvals(&approvals));
    let mut adapter = AgentForwardingAdapter::new(AgentServer::new(&store), policy, 7);
    let request = extension_frame(27, b"session-bind@openssh.com", &session_bind_contents());
    assert_eq!(adapter.push(&request[..8]).expect("partial request").len(), 0);
    let refusal = adapter.push(&request[8..]).expect("opaque refusal");
    assert_eq!(refusal.len(), 1);
    assert_eq!(refusal[0].data, frame(&[5]));
    assert_eq!(store.extensions.load(Ordering::SeqCst), 0);
    assert_eq!(store.signs.load(Ordering::SeqCst), 0);
    assert_eq!(approvals.load(Ordering::SeqCst), 0);
    let identities = adapter.push(&frame(&[11])).expect("healthy query");
    assert!(
        matches!(AgentMessage::decode_frame(&identities[0].data), Ok(AgentMessage::IdentitiesAnswer { identities }) if identities.len() == 1)
    );
    let sign = AgentMessage::SignRequest {
        key_blob: b"synthetic-key".to_vec(),
        data: b"payload".to_vec(),
        flags: 0,
    }
    .encode_frame()
    .expect("sign frame");
    let response = adapter.push(&sign).expect("healthy sign");
    assert_eq!(
        AgentMessage::decode_frame(&response[0].data),
        Ok(AgentMessage::SignResponse { signature: b"synthetic-signature".to_vec() })
    );
    assert_eq!(store.signs.load(Ordering::SeqCst), 1);
    assert_eq!(approvals.load(Ordering::SeqCst), 1);
    adapter.finish().expect("healthy close");
}

struct Approvals<'a>(&'a AtomicUsize);

impl AgentForwardingAuthorizer for Approvals<'_> {
    fn authorize_signature(&self, _: &[u8], _: &[u8], _: u32) -> Result<(), AgentError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[test]
fn extension_response_debug_redacts_name_and_contents() {
    let debug = format!(
        "{:?}",
        AgentMessage::ExtensionResponse {
            name: b"private-name@example.com".to_vec(),
            contents: b"private-content".to_vec(),
        }
    );
    assert!(debug.contains("name_len"));
    assert!(debug.contains("contents_len"));
    assert!(!debug.contains("private"));
}
