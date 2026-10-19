// SPDX-License-Identifier: Apache-2.0

use std::io::{self, Read, Write};

use scoplen_ssh::{
    AgentChannel, AgentClient, AgentError, AgentMessage, FramedAgentChannel, MAX_AGENT_FRAME,
    PageantAgentChannel,
};

struct FaultStream {
    response: Vec<u8>,
    read_offset: usize,
    written: Vec<u8>,
    read_calls: usize,
    write_calls: usize,
    flush_calls: usize,
    read_error_at: Option<usize>,
    write_error_at: Option<usize>,
    flush_error: bool,
}

impl FaultStream {
    fn new(response: Vec<u8>) -> Self {
        Self {
            response,
            read_offset: 0,
            written: Vec::new(),
            read_calls: 0,
            write_calls: 0,
            flush_calls: 0,
            read_error_at: None,
            write_error_at: None,
            flush_error: false,
        }
    }
}

impl Read for FaultStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.read_calls += 1;
        if self.read_error_at == Some(self.read_offset) {
            self.read_error_at = None;
            return Err(io::Error::new(io::ErrorKind::TimedOut, "one-time read timeout"));
        }
        if self.read_offset == self.response.len() {
            return Ok(0);
        }
        buffer[0] = self.response[self.read_offset];
        self.read_offset += 1;
        Ok(1)
    }
}

impl Write for FaultStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.write_calls += 1;
        if self.write_error_at == Some(self.written.len()) {
            self.write_error_at = None;
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "one-time write failure"));
        }
        self.written.push(buffer[0]);
        Ok(1)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_calls += 1;
        if self.flush_error {
            self.flush_error = false;
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "one-time flush failure"));
        }
        Ok(())
    }
}

fn request() -> Vec<u8> {
    AgentMessage::RequestIdentities.encode_frame().expect("request frame")
}

#[test]
fn late_response_after_timeout_is_not_mistaken_for_the_next_request() {
    let response = AgentMessage::IdentitiesAnswer { identities: Vec::new() }
        .encode_frame()
        .expect("valid response");
    let mut stream = FaultStream::new(response.clone());
    stream.read_error_at = Some(0);
    let mut client = AgentClient::new(FramedAgentChannel::new(stream));

    assert!(matches!(client.identities(), Err(AgentError::Transport(_))));
    assert_eq!(client.identities(), Err(AgentError::ChannelUnusable));

    let stream = client.into_inner().into_inner();
    assert_eq!(stream.written, request());
    assert_eq!(stream.read_calls, 1);
    assert_eq!(stream.read_offset, 0);
    assert_eq!(
        AgentMessage::decode_frame(&response),
        Ok(AgentMessage::IdentitiesAnswer { identities: Vec::new() })
    );
}

#[test]
fn every_failed_exchange_after_io_stops_further_dispatch() {
    let success = AgentMessage::Success.encode_frame().expect("success response");
    let cases = [
        (
            "partial write",
            {
                let mut stream = FaultStream::new(success.clone());
                stream.write_error_at = Some(2);
                stream
            },
            None,
            (0, 3, 0),
        ),
        (
            "flush",
            {
                let mut stream = FaultStream::new(success.clone());
                stream.flush_error = true;
                stream
            },
            None,
            (0, 5, 1),
        ),
        (
            "partial header",
            {
                let mut stream = FaultStream::new(success.clone());
                stream.read_error_at = Some(2);
                stream
            },
            None,
            (3, 5, 1),
        ),
        (
            "partial body",
            {
                let response = AgentMessage::IdentitiesAnswer { identities: Vec::new() }
                    .encode_frame()
                    .expect("response with multi-byte body");
                let mut stream = FaultStream::new(response);
                stream.read_error_at = Some(5);
                stream
            },
            None,
            (6, 5, 1),
        ),
        (
            "empty frame",
            FaultStream::new(vec![0, 0, 0, 0]),
            Some(AgentError::MalformedFrame("empty agent payload")),
            (4, 5, 1),
        ),
        (
            "oversized frame",
            FaultStream::new(
                (u32::try_from(MAX_AGENT_FRAME).expect("frame limit") + 1).to_be_bytes().to_vec(),
            ),
            Some(AgentError::FrameTooLarge),
            (4, 5, 1),
        ),
        (
            "invalid payload",
            FaultStream::new(vec![0, 0, 0, 1, 0xff]),
            Some(AgentError::UnsupportedMessage(0xff)),
            (5, 5, 1),
        ),
    ];

    for (name, stream, expected_error, expected_calls) in cases {
        let mut channel = FramedAgentChannel::new(stream);
        let request = request();
        let first = channel.exchange(&request);
        if let Some(expected_error) = expected_error {
            assert_eq!(first, Err(expected_error), "{name}");
        } else {
            assert!(matches!(first, Err(AgentError::Transport(_))), "{name}: {first:?}");
        }
        assert_eq!(channel.exchange(&request), Err(AgentError::ChannelUnusable), "{name}");

        let stream = channel.into_inner();
        let expected_written = if name == "partial write" { &request[..2] } else { &request };
        assert_eq!(stream.written, expected_written, "{name}: second request was dispatched");
        assert_eq!(
            (stream.read_calls, stream.write_calls, stream.flush_calls),
            expected_calls,
            "{name}: second request touched the stream"
        );
    }
}

#[test]
fn local_validation_does_not_poison_the_channel() {
    let success = AgentMessage::Success.encode_frame().expect("success response");
    let mut channel = FramedAgentChannel::new(FaultStream::new(success.clone()));
    let request = request();

    assert_eq!(
        channel.exchange(&[0, 0, 0, 0]),
        Err(AgentError::MalformedFrame("empty agent payload"))
    );
    assert_eq!(channel.exchange(&request), Ok(success));

    let stream = channel.into_inner();
    assert_eq!(stream.written, request);
}

#[test]
fn complete_agent_refusal_does_not_poison_the_client() {
    let mut responses = AgentMessage::Failure.encode_frame().expect("failure response");
    responses.extend_from_slice(&AgentMessage::Success.encode_frame().expect("success response"));
    let mut client = AgentClient::new(FramedAgentChannel::new(FaultStream::new(responses)));

    assert_eq!(client.remove_all_identities(), Err(AgentError::AgentFailure));
    assert_eq!(client.remove_all_identities(), Ok(()));

    let request = AgentMessage::RemoveAllIdentities.encode_frame().expect("request frame");
    assert_eq!(client.into_inner().into_inner().written, [request.clone(), request].concat());
}

#[test]
fn pageant_named_pipe_uses_the_same_unusable_state() {
    let mut stream =
        FaultStream::new(AgentMessage::Failure.encode_frame().expect("failure response"));
    stream.read_error_at = Some(0);
    let mut channel = PageantAgentChannel::new(stream);
    let request = request();

    assert!(matches!(channel.exchange(&request), Err(AgentError::Transport(_))));
    assert_eq!(channel.exchange(&request), Err(AgentError::ChannelUnusable));
    assert_eq!(channel.into_inner().written, request);
}
