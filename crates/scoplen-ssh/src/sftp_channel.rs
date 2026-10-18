//! Bounded SFTP v3 framing over one authenticated SSH session channel.

use std::{
    collections::{BTreeMap, VecDeque},
    io,
};

use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    ChannelEvent, ClientChannelStream, ClientConnection, ClientError, MAX_SFTP_PACKET, SftpClient,
    SftpError, SftpExtension, SftpLimits, SftpPacket,
};

const LIMITS_EXTENSION: &[u8] = b"limits@openssh.com";

/// Errors raised while opening or using an SFTP SSH channel.
#[derive(Debug, Error)]
pub enum SftpChannelError {
    /// The SSH channel could not be opened or used.
    #[error(transparent)]
    Ssh(#[from] ClientError),
    /// The peer rejected the SFTP subsystem request.
    #[error("SSH server rejected the SFTP subsystem")]
    SubsystemRejected,
    /// The SSH channel ended before the subsystem was accepted.
    #[error("SSH channel closed before the SFTP subsystem started")]
    SubsystemClosed,
    /// The peer sent channel output before accepting the subsystem.
    #[error("SSH server sent an unexpected SFTP subsystem response")]
    UnexpectedSubsystemResponse,
    /// The SFTP packet or version handshake was invalid.
    #[error(transparent)]
    Protocol(#[from] SftpError),
    /// The peer closed the stream between complete packets.
    #[error("SFTP channel closed")]
    Closed,
    /// The peer closed the stream partway through a packet.
    #[error("SFTP channel ended inside a packet")]
    Truncated,
    /// Reading or writing the channel failed.
    #[error("SFTP channel I/O failed: {0}")]
    Io(#[from] io::Error),
    /// The server rejected a transfer request with an SFTP status code.
    #[error("SFTP server returned status code {code}")]
    RemoteStatus { code: u32 },
}

/// Progress reported after a contiguous transfer chunk is committed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SftpTransferProgress {
    /// Remote offset immediately after the committed bytes.
    pub offset: u64,
    /// Total bytes committed during this transfer.
    pub transferred: u64,
    /// Expected final remote offset, when known.
    pub total: Option<u64>,
}

/// One SFTP v3 subsystem on an existing authenticated SSH connection.
///
/// Requests built by [`SftpClient`] can be sent with [`Self::write_packet`], then correlated with
/// responses from [`Self::read_packet`]. Keeping this channel and a terminal open on the same
/// [`ClientConnection`] reuses one SSH transport.
#[derive(Debug)]
pub struct SftpChannel {
    stream: ClientChannelStream,
    extensions: Vec<SftpExtension>,
}

/// A negotiated SFTP channel with bounded request correlation and pipelining.
#[derive(Debug)]
pub struct SftpSession {
    channel: SftpChannel,
    client: SftpClient,
    limits: Option<SftpLimits>,
}

impl SftpSession {
    /// Open and negotiate an SFTP v3 channel with a bounded outstanding-request pipeline.
    ///
    /// # Errors
    ///
    /// Returns an error when the SSH subsystem or SFTP handshake fails, or when the pipeline
    /// bound is outside [`crate::MAX_SFTP_OUTSTANDING`].
    pub async fn open(
        connection: &ClientConnection,
        max_outstanding: usize,
    ) -> Result<Self, SftpChannelError> {
        let channel = SftpChannel::open(connection).await?;
        let mut client = SftpClient::new(max_outstanding)?;
        client.accept_version(&SftpPacket::Version {
            version: 3,
            extensions: channel.extensions.clone(),
        })?;
        let mut session = Self { channel, client, limits: None };
        session.limits = session.request_limits().await?;
        Ok(session)
    }

    /// Return the bounded extensions advertised by the server.
    #[must_use]
    pub fn extensions(&self) -> &[SftpExtension] {
        self.channel.extensions()
    }

    /// Borrow the request builder and bounded correlation state.
    #[must_use]
    pub fn client_mut(&mut self) -> &mut SftpClient {
        &mut self.client
    }

    /// Number of requests awaiting a response.
    #[must_use]
    pub fn pending_requests(&self) -> usize {
        self.client.pending_requests()
    }

    /// Return the transfer limits negotiated during [`Self::open`], when the server advertised
    /// `limits@openssh.com`.
    #[must_use]
    pub fn limits(&self) -> Option<SftpLimits> {
        self.limits
    }

    /// Return the server's bounded transfer limits, requesting them once when advertised.
    ///
    /// A previously negotiated value is returned from the session cache. A server that does not
    /// advertise `limits@openssh.com` returns `Ok(None)` without sending an extension request. An
    /// advertised extension must answer with one exact, bounded limits body; malformed or
    /// unexpected responses are returned as protocol errors.
    ///
    /// # Errors
    ///
    /// Returns an error when the request cannot be queued, the channel I/O fails, the response
    /// references an unknown request, or the peer returns a malformed limits body.
    pub async fn request_limits(&mut self) -> Result<Option<SftpLimits>, SftpChannelError> {
        if self.limits.is_some() {
            return Ok(self.limits);
        }
        if !self.extensions().iter().any(|extension| extension.name == LIMITS_EXTENSION) {
            self.limits = None;
            return Ok(None);
        }
        let request = self.client.request_limits()?;
        self.send_request(&request).await?;
        let response = self.read_response().await?;
        let limits = response.limits_response()?;
        self.limits = Some(limits);
        Ok(Some(limits))
    }

    /// Send a request previously built by [`Self::client_mut`].
    ///
    /// # Errors
    ///
    /// Returns an error when the packet does not refer to a request tracked by this session or
    /// the channel cannot write it. A failed write releases its request slot.
    pub async fn send_request(&mut self, packet: &SftpPacket) -> Result<(), SftpChannelError> {
        let Some(id) = packet.request_id() else {
            return Err(SftpError::Malformed("request has no request id").into());
        };
        if !self.client.tracks_request(id) {
            return Err(SftpError::UnknownRequest.into());
        }
        if let Err(error) = self.channel.write_packet(packet).await {
            self.client.release_request(id);
            return Err(error);
        }
        Ok(())
    }

    /// Read and correlate one response, releasing its pipeline slot.
    ///
    /// # Errors
    ///
    /// Returns an error when the channel ends, the packet is malformed, or its request id is not
    /// currently pending.
    pub async fn read_response(&mut self) -> Result<SftpPacket, SftpChannelError> {
        let packet = self.channel.read_packet().await?;
        self.client.accept_response(&packet)?;
        Ok(packet)
    }

    /// Download a handle into an async sink with bounded pipelining and resume-by-offset.
    ///
    /// `start_offset` is the remote offset represented by the sink's current position. `total`,
    /// when present, is the remote end offset. A missing total reads until the server returns
    /// `SSH_FX_EOF`. The callback runs after each contiguous chunk is written.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid bounds, a failed or rejected request, malformed responses,
    /// or sink I/O. A failed transfer releases all request slots reserved by this operation.
    #[allow(clippy::too_many_arguments)]
    pub async fn download_to<W, F>(
        &mut self,
        handle: &[u8],
        start_offset: u64,
        total: Option<u64>,
        chunk_size: u32,
        pipeline: usize,
        sink: &mut W,
        progress: F,
    ) -> Result<u64, SftpChannelError>
    where
        W: AsyncWrite + Unpin,
        F: FnMut(SftpTransferProgress),
    {
        if total.is_some_and(|end| end < start_offset) {
            return Err(SftpError::InvalidValue("transfer range").into());
        }
        let chunk_size = effective_chunk_size(chunk_size, self.limits, true)?;
        validate_transfer(handle, chunk_size, pipeline, self.pending_requests())?;
        let result = self
            .download_to_inner(handle, start_offset, total, chunk_size, pipeline, sink, progress)
            .await;
        if result.is_err() {
            self.client.clear_pending();
        }
        result
    }

    #[allow(clippy::too_many_arguments)]
    async fn download_to_inner<W, F>(
        &mut self,
        handle: &[u8],
        start_offset: u64,
        total: Option<u64>,
        chunk_size: u32,
        pipeline: usize,
        sink: &mut W,
        mut progress: F,
    ) -> Result<u64, SftpChannelError>
    where
        W: AsyncWrite + Unpin,
        F: FnMut(SftpTransferProgress),
    {
        let mut next_offset = start_offset;
        let mut committed_offset = start_offset;
        let mut transferred = 0_u64;
        let mut eof_at = None::<u64>;
        let mut inflight = BTreeMap::<u32, (u64, u32)>::new();
        let mut ready = BTreeMap::<u64, Vec<u8>>::new();
        let mut retry = VecDeque::<(u64, u32)>::new();
        progress(SftpTransferProgress { offset: start_offset, transferred, total });

        loop {
            while inflight.len() < pipeline && self.client.available_requests() > 0 {
                let (offset, length) = if let Some((offset, length)) = retry.pop_front() {
                    if eof_at.is_some_and(|end| offset >= end) {
                        continue;
                    }
                    let length = eof_at.map_or(length, |end| {
                        u32::try_from((end - offset).min(u64::from(length))).unwrap_or(length)
                    });
                    (offset, length)
                } else if eof_at.is_none()
                    && ready.is_empty()
                    && total.is_none_or(|end| next_offset < end)
                {
                    let remaining = total.map(|end| end.saturating_sub(next_offset));
                    let length = remaining.map_or(chunk_size, |value| {
                        u32::try_from(value.min(u64::from(chunk_size))).unwrap_or(chunk_size)
                    });
                    let offset = next_offset;
                    next_offset = next_offset
                        .checked_add(u64::from(length))
                        .ok_or(SftpError::InvalidValue("read offset"))?;
                    (offset, length)
                } else {
                    break;
                };
                let request = self.client.read(handle.to_vec(), offset, length)?;
                let id = request.request_id().ok_or(SftpError::Malformed("read request id"))?;
                self.send_request(&request).await?;
                inflight.insert(id, (offset, length));
            }

            if inflight.is_empty() {
                if ready.is_empty() && total.or(eof_at) == Some(committed_offset) {
                    break;
                }
                if eof_at.is_some() {
                    return Err(SftpChannelError::RemoteStatus { code: 1 });
                }
                return Err(SftpError::Malformed("non-contiguous read responses").into());
            }
            let response = self.read_response().await?;
            let id = response.request_id().ok_or(SftpError::Malformed("read response id"))?;
            let Some((offset, expected)) = inflight.remove(&id) else {
                return Err(SftpError::UnknownRequest.into());
            };
            match response {
                SftpPacket::Data { data, .. } => {
                    if data.is_empty() {
                        return Err(SftpError::Malformed("empty read response").into());
                    }
                    if data.len() > expected as usize
                        || eof_at.is_some_and(|end| offset + data.len() as u64 > end)
                    {
                        return Err(SftpError::InvalidValue("read response length").into());
                    }
                    let received = u32::try_from(data.len())
                        .map_err(|_| SftpError::InvalidValue("read response length"))?;
                    if data.len() < expected as usize {
                        retry.push_back((offset + u64::from(received), expected - received));
                    }
                    if ready.insert(offset, data).is_some() {
                        return Err(SftpError::Malformed("overlapping read response").into());
                    }
                }
                SftpPacket::Status { code: 1, .. } => {
                    if offset < committed_offset || ready.range(offset..).next().is_some() {
                        return Err(SftpError::Malformed("read data after EOF").into());
                    }
                    eof_at = Some(eof_at.map_or(offset, |end| end.min(offset)));
                }
                SftpPacket::Status { code, .. } => {
                    return Err(SftpChannelError::RemoteStatus { code });
                }
                _ => return Err(SftpError::Malformed("read response type").into()),
            }

            while let Some(data) = ready.remove(&committed_offset) {
                sink.write_all(&data).await?;
                committed_offset = committed_offset
                    .checked_add(data.len() as u64)
                    .ok_or(SftpError::InvalidValue("transfer offset"))?;
                transferred = transferred
                    .checked_add(data.len() as u64)
                    .ok_or(SftpError::InvalidValue("transfer length"))?;
                progress(SftpTransferProgress { offset: committed_offset, transferred, total });
            }
        }
        sink.flush().await?;
        Ok(transferred)
    }

    /// Upload bytes to a remote handle with bounded pipelining and resume-by-offset.
    ///
    /// `start_offset` is the remote offset represented by the first byte in `data`; callers can
    /// resume a local source by slicing it at the matching offset. The callback runs after each
    /// successful write response.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid bounds, failed writes, malformed responses, or a non-zero
    /// remote status. A failed transfer releases all request slots reserved by this operation.
    pub async fn upload(
        &mut self,
        handle: &[u8],
        start_offset: u64,
        data: &[u8],
        chunk_size: u32,
        pipeline: usize,
        progress: impl FnMut(SftpTransferProgress),
    ) -> Result<u64, SftpChannelError> {
        start_offset
            .checked_add(data.len() as u64)
            .ok_or(SftpError::InvalidValue("transfer length"))?;
        let chunk_size = effective_chunk_size(chunk_size, self.limits, false)?;
        validate_transfer(handle, chunk_size, pipeline, self.pending_requests())?;
        let result =
            self.upload_inner(handle, start_offset, data, chunk_size, pipeline, progress).await;
        if result.is_err() {
            self.client.clear_pending();
        }
        result
    }

    async fn upload_inner(
        &mut self,
        handle: &[u8],
        start_offset: u64,
        data: &[u8],
        chunk_size: u32,
        pipeline: usize,
        mut progress: impl FnMut(SftpTransferProgress),
    ) -> Result<u64, SftpChannelError> {
        let total = start_offset + data.len() as u64;
        let mut next = 0_usize;
        let mut transferred = 0_u64;
        let mut committed_offset = start_offset;
        let mut inflight = BTreeMap::<u32, (u64, usize)>::new();
        let mut completed = BTreeMap::<u64, usize>::new();
        progress(SftpTransferProgress { offset: start_offset, transferred, total: Some(total) });

        loop {
            while next < data.len()
                && inflight.len() < pipeline
                && self.client.available_requests() > 0
            {
                let end = (next + chunk_size as usize).min(data.len());
                let request = self.client.write(
                    handle.to_vec(),
                    start_offset + next as u64,
                    data[next..end].to_vec(),
                )?;
                let id = request.request_id().ok_or(SftpError::Malformed("write request id"))?;
                self.send_request(&request).await?;
                inflight.insert(id, (start_offset + next as u64, end - next));
                next = end;
            }
            if inflight.is_empty() {
                break;
            }
            let response = self.read_response().await?;
            let id = response.request_id().ok_or(SftpError::Malformed("write response id"))?;
            let Some((offset, length)) = inflight.remove(&id) else {
                return Err(SftpError::UnknownRequest.into());
            };
            match response {
                SftpPacket::Status { code: 0, .. } => {
                    completed.insert(offset, length);
                    while let Some(length) = completed.remove(&committed_offset) {
                        committed_offset = committed_offset
                            .checked_add(length as u64)
                            .ok_or(SftpError::InvalidValue("transfer offset"))?;
                        transferred = transferred
                            .checked_add(length as u64)
                            .ok_or(SftpError::InvalidValue("transfer length"))?;
                        progress(SftpTransferProgress {
                            offset: committed_offset,
                            transferred,
                            total: Some(total),
                        });
                    }
                }
                SftpPacket::Status { code, .. } => {
                    return Err(SftpChannelError::RemoteStatus { code });
                }
                _ => return Err(SftpError::Malformed("write response type").into()),
            }
        }
        Ok(transferred)
    }
}

fn effective_chunk_size(
    requested: u32,
    limits: Option<SftpLimits>,
    read: bool,
) -> Result<u32, SftpChannelError> {
    let local_limit = u64::try_from(MAX_SFTP_PACKET - 64).expect("SFTP packet bound fits u64");
    let server_limit = limits.map_or(local_limit, |limits| {
        let packet_limit = limits.max_packet_length.saturating_sub(64);
        packet_limit.min(if read { limits.max_read_length } else { limits.max_write_length })
    });
    let bounded = u64::from(requested).min(server_limit).min(local_limit);
    u32::try_from(bounded).map_err(|_| SftpError::InvalidValue("transfer chunk size").into())
}

fn validate_transfer(
    handle: &[u8],
    chunk_size: u32,
    pipeline: usize,
    pending: usize,
) -> Result<(), SftpChannelError> {
    if handle.is_empty() {
        return Err(SftpError::InvalidValue("transfer handle").into());
    }
    if handle.len() > crate::MAX_SFTP_HANDLE {
        return Err(SftpError::FieldTooLarge("transfer handle").into());
    }
    if chunk_size == 0 || usize::try_from(chunk_size).unwrap_or(usize::MAX) > MAX_SFTP_PACKET - 64 {
        return Err(SftpError::InvalidValue("transfer chunk size").into());
    }
    if pipeline == 0 || pipeline > crate::MAX_SFTP_OUTSTANDING {
        return Err(SftpError::InvalidValue("transfer pipeline").into());
    }
    if pending != 0 {
        return Err(SftpError::InvalidValue("transfer requires an empty pipeline").into());
    }
    Ok(())
}

impl SftpChannel {
    /// Open a session, require SFTP subsystem acceptance, and negotiate SFTP version 3.
    ///
    /// # Errors
    ///
    /// Returns an error when the SSH channel cannot be opened, the subsystem is rejected, or the
    /// peer sends an invalid or truncated version packet.
    pub async fn open(connection: &ClientConnection) -> Result<Self, SftpChannelError> {
        let mut channel = connection.open_session().await?;
        channel.request_subsystem("sftp", true).await?;
        match channel.next_event().await? {
            Some(ChannelEvent::Success) => {}
            Some(ChannelEvent::Failure) => return Err(SftpChannelError::SubsystemRejected),
            None | Some(ChannelEvent::Close | ChannelEvent::Eof) => {
                return Err(SftpChannelError::SubsystemClosed);
            }
            Some(_) => return Err(SftpChannelError::UnexpectedSubsystemResponse),
        }

        let mut sftp = Self { stream: channel.into_stream(), extensions: Vec::new() };
        sftp.write_packet(&SftpPacket::Init { version: 3 }).await?;
        let version = sftp.read_packet().await?;
        let mut handshake = SftpClient::new(1)?;
        handshake.accept_version(&version)?;
        if let SftpPacket::Version { extensions, .. } = version {
            sftp.extensions = extensions;
        }
        Ok(sftp)
    }

    /// Return the bounded extensions advertised in the v3 VERSION packet.
    #[must_use]
    pub fn extensions(&self) -> &[SftpExtension] {
        &self.extensions
    }

    /// Write one complete SFTP packet over the SSH channel.
    ///
    /// # Errors
    ///
    /// Returns an error when packet encoding rejects a bounded field or the SSH channel cannot
    /// accept the complete frame.
    pub async fn write_packet(&mut self, packet: &SftpPacket) -> Result<(), SftpChannelError> {
        let frame = packet.encode()?;
        self.stream.write_all(&frame).await?;
        self.stream.flush().await?;
        Ok(())
    }

    /// Read one complete SFTP packet, rejecting its length before allocating the body.
    ///
    /// # Errors
    ///
    /// Returns an error when the peer closes or truncates the channel, declares an oversized
    /// packet, or sends an invalid SFTP frame.
    pub async fn read_packet(&mut self) -> Result<SftpPacket, SftpChannelError> {
        let mut length = [0_u8; 4];
        if self.stream.read(&mut length[..1]).await? == 0 {
            return Err(SftpChannelError::Closed);
        }
        read_exact(&mut self.stream, &mut length[1..]).await?;
        let body_len = u32::from_be_bytes(length) as usize;
        if body_len > MAX_SFTP_PACKET - 4 {
            return Err(SftpError::PacketTooLarge.into());
        }
        if body_len == 0 {
            return Err(SftpError::Malformed("empty packet").into());
        }
        let mut frame = vec![0_u8; body_len + 4];
        frame[..4].copy_from_slice(&length);
        read_exact(&mut self.stream, &mut frame[4..]).await?;
        Ok(SftpPacket::decode(&frame)?)
    }
}

async fn read_exact(
    stream: &mut ClientChannelStream,
    buffer: &mut [u8],
) -> Result<(), SftpChannelError> {
    match stream.read_exact(buffer).await {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
            Err(SftpChannelError::Truncated)
        }
        Err(error) => Err(SftpChannelError::Io(error)),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use russh::keys::PrivateKey;
    use ssh_key::Algorithm;
    use tokio::net::TcpListener;

    use super::*;
    use crate::{ClientConfig, HostKey, SftpAttributes, SftpNameEntry, SftpStatvfs};

    struct SftpServer {
        buffer: Vec<u8>,
        file: Vec<u8>,
        advertise_limits: bool,
        advertise_statvfs: bool,
        fsync_handle_open: Option<bool>,
        read_reply_limit: Option<usize>,
        reorder_first_reads: bool,
        deferred_read_response: Option<SftpPacket>,
    }

    impl SftpServer {
        fn version_response(&self) -> SftpPacket {
            let mut extensions = Vec::new();
            if self.advertise_limits {
                extensions.push(SftpExtension::new(b"limits@openssh.com", b"1").unwrap());
            }
            if self.advertise_statvfs {
                extensions.push(SftpExtension::new(b"statvfs@openssh.com", b"2").unwrap());
            }
            if self.fsync_handle_open.is_some() {
                extensions.push(SftpExtension::new(b"fsync@openssh.com", b"1").unwrap());
            }
            SftpPacket::Version { version: 3, extensions }
        }

        fn limits_response(id: u32) -> SftpPacket {
            SftpPacket::ExtendedReply {
                id,
                data: SftpLimits {
                    max_packet_length: 256 * 1024,
                    max_read_length: 128 * 1024,
                    max_write_length: 64 * 1024,
                    max_open_handles: 128,
                }
                .encode(),
            }
        }

        fn statvfs_response(id: u32, data: &[u8]) -> SftpPacket {
            if data == b"\0\0\0\x01." {
                SftpPacket::ExtendedReply {
                    id,
                    data: SftpStatvfs {
                        block_size: 4096,
                        fragment_size: 4096,
                        blocks: 100,
                        free_blocks: 80,
                        available_blocks: 70,
                        files: 50,
                        free_files: 40,
                        available_files: 30,
                        filesystem_id: 1,
                        flags: 0,
                        name_max: 255,
                    }
                    .encode(),
                }
            } else {
                SftpPacket::Status { id, code: 2, message: Vec::new(), language: Vec::new() }
            }
        }

        fn open_fsync_handle(&mut self, id: u32) -> SftpPacket {
            self.fsync_handle_open = Some(true);
            SftpPacket::Handle { id, handle: b"h".to_vec() }
        }

        fn close_fsync_handle(&mut self, id: u32, handle: &[u8]) -> SftpPacket {
            let code = if handle == b"h" && self.fsync_handle_open == Some(true) {
                self.fsync_handle_open = Some(false);
                0
            } else {
                4
            };
            SftpPacket::Status { id, code, message: Vec::new(), language: Vec::new() }
        }

        fn fsync_response(&self, id: u32, data: &[u8]) -> SftpPacket {
            let code =
                if data == b"\0\0\0\x01h" && self.fsync_handle_open == Some(true) { 0 } else { 4 };
            SftpPacket::Status { id, code, message: Vec::new(), language: Vec::new() }
        }
    }

    #[test]
    fn transfer_chunks_respect_negotiated_read_and_write_limits() {
        let limits = Some(SftpLimits {
            max_packet_length: 256 * 1024,
            max_read_length: 128,
            max_write_length: 64,
            max_open_handles: 8,
        });
        assert_eq!(effective_chunk_size(4096, limits, true).unwrap(), 128);
        assert_eq!(effective_chunk_size(4096, limits, false).unwrap(), 64);
        let packet_limited = Some(SftpLimits {
            max_packet_length: 128,
            max_read_length: 4096,
            max_write_length: 4096,
            max_open_handles: 8,
        });
        assert_eq!(effective_chunk_size(4096, packet_limited, true).unwrap(), 64);
        assert_eq!(
            effective_chunk_size(u32::try_from(MAX_SFTP_PACKET).unwrap(), None, true).unwrap(),
            u32::try_from(MAX_SFTP_PACKET - 64).unwrap()
        );
    }

    impl russh::server::Handler for SftpServer {
        type Error = russh::Error;

        async fn auth_password(
            &mut self,
            _user: &str,
            _password: &str,
        ) -> Result<russh::server::Auth, Self::Error> {
            Ok(russh::server::Auth::Accept)
        }

        async fn channel_open_session(
            &mut self,
            _channel: russh::Channel<russh::server::Msg>,
            reply: russh::server::ChannelOpenHandle,
            _session: &mut russh::server::Session,
        ) -> Result<(), Self::Error> {
            reply.accept().await;
            Ok(())
        }

        async fn subsystem_request(
            &mut self,
            channel: russh::ChannelId,
            name: &str,
            session: &mut russh::server::Session,
        ) -> Result<(), Self::Error> {
            if name == "sftp" {
                let _ = session.channel_success(channel);
            } else {
                let _ = session.channel_failure(channel);
            }
            Ok(())
        }

        async fn data(
            &mut self,
            channel: russh::ChannelId,
            data: &[u8],
            session: &mut russh::server::Session,
        ) -> Result<(), Self::Error> {
            self.buffer.extend_from_slice(data);
            loop {
                if self.buffer.len() < 4 {
                    return Ok(());
                }
                let body_len = u32::from_be_bytes(self.buffer[..4].try_into().unwrap()) as usize;
                if body_len > MAX_SFTP_PACKET - 4 || self.buffer.len() < body_len + 4 {
                    return Ok(());
                }
                let frame: Vec<_> = self.buffer.drain(..body_len + 4).collect();
                let Ok(packet) = SftpPacket::decode(&frame) else {
                    return Ok(());
                };
                let is_read = matches!(packet, SftpPacket::Read { .. });
                let response = match packet {
                    SftpPacket::Init { .. } => self.version_response(),
                    SftpPacket::Open { id, .. } if self.fsync_handle_open.is_some() => {
                        self.open_fsync_handle(id)
                    }
                    SftpPacket::Close { id, handle } if self.fsync_handle_open.is_some() => {
                        self.close_fsync_handle(id, &handle)
                    }
                    SftpPacket::Realpath { id, .. } => SftpPacket::Name {
                        id,
                        entries: vec![
                            SftpNameEntry::new(
                                b"/srv".to_vec(),
                                Vec::new(),
                                SftpAttributes::default(),
                            )
                            .unwrap(),
                        ],
                    },
                    SftpPacket::Read { id, offset, length, .. } => match usize::try_from(offset) {
                        Ok(start) if start < self.file.len() => {
                            let end = start
                                .saturating_add(
                                    self.read_reply_limit
                                        .unwrap_or(length as usize)
                                        .min(length as usize),
                                )
                                .min(self.file.len());
                            SftpPacket::Data { id, data: self.file[start..end].to_vec() }
                        }
                        _ => SftpPacket::Status {
                            id,
                            code: 1,
                            message: Vec::new(),
                            language: Vec::new(),
                        },
                    },
                    SftpPacket::Write { id, offset, data, .. } => {
                        let Ok(start) = usize::try_from(offset) else {
                            return Ok(());
                        };
                        let end = start.saturating_add(data.len());
                        if end > self.file.len() {
                            self.file.resize(end, 0);
                        }
                        self.file[start..end].copy_from_slice(&data);
                        SftpPacket::Status {
                            id,
                            code: 0,
                            message: Vec::new(),
                            language: Vec::new(),
                        }
                    }
                    SftpPacket::Extended { id, name, .. }
                        if name == b"limits@openssh.com" && self.advertise_limits =>
                    {
                        Self::limits_response(id)
                    }
                    SftpPacket::Extended { id, name, data }
                        if name == b"statvfs@openssh.com" && self.advertise_statvfs =>
                    {
                        Self::statvfs_response(id, &data)
                    }
                    SftpPacket::Extended { id, name, data }
                        if name == b"fsync@openssh.com" && self.fsync_handle_open.is_some() =>
                    {
                        self.fsync_response(id, &data)
                    }
                    _ => continue,
                };
                if is_read && self.reorder_first_reads {
                    if self.deferred_read_response.is_none() {
                        self.deferred_read_response = Some(response);
                        continue;
                    }
                    self.reorder_first_reads = false;
                    let _ = session.data(channel, response.encode().expect("SFTP response"));
                    let deferred = self.deferred_read_response.take().expect("deferred read");
                    let _ =
                        session.data(channel, deferred.encode().expect("deferred SFTP response"));
                    continue;
                }
                let _ = session.data(channel, response.encode().expect("SFTP response"));
            }
        }
    }

    async fn transfer_session(
        file: Vec<u8>,
        read_reply_limit: Option<usize>,
        reorder_first_reads: bool,
    ) -> (ClientConnection, SftpSession) {
        let mut server_config = russh::server::Config::default();
        server_config.keys.push(
            PrivateKey::random(
                &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
                Algorithm::Ed25519,
            )
            .expect("server key"),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind server");
        let address = listener.local_addr().expect("server address");
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept client");
            let _ = russh::server::run_stream(
                Arc::new(server_config),
                stream,
                SftpServer {
                    buffer: Vec::new(),
                    file,
                    advertise_limits: false,
                    advertise_statvfs: false,
                    fsync_handle_open: None,
                    read_reply_limit,
                    reorder_first_reads,
                    deferred_read_response: None,
                },
            )
            .await;
        });
        let verifier = |_host: &str, _key: &HostKey| Ok(());
        let config = ClientConfig::new("127.0.0.1", address.port(), verifier).expect("config");
        let mut connection = ClientConnection::connect(config).await.expect("connect client");
        connection.authenticate_password("user", b"password").await.expect("authenticate client");
        let session = SftpSession::open(&connection, 2).await.expect("open sftp session");
        (connection, session)
    }

    #[tokio::test]
    async fn short_read_resumes_missing_ranges_before_completing_download() {
        let (connection, mut session) = transfer_session(b"abcdef".to_vec(), Some(1), true).await;
        for total in [Some(6), None] {
            let mut downloaded = Vec::new();
            let mut progress = Vec::new();
            let count = session
                .download_to(b"h", 0, total, 2, 2, &mut downloaded, |event| progress.push(event))
                .await
                .expect("short-read download");
            assert_eq!(count, 6);
            assert_eq!(downloaded, b"abcdef");
            assert_eq!(progress.first().map(|event| event.offset), Some(0));
            assert_eq!(progress.last().map(|event| event.offset), Some(6));
            assert!(progress.windows(2).all(|pair| pair[0].offset < pair[1].offset));
            assert_eq!(session.pending_requests(), 0);
        }
        connection.disconnect().await.expect("disconnect client");
    }

    #[tokio::test]
    async fn premature_eof_and_empty_data_are_not_successful_downloads() {
        let (connection, mut session) = transfer_session(b"abc".to_vec(), None, false).await;
        let mut downloaded = Vec::new();
        let error = session
            .download_to(b"h", 0, Some(6), 2, 2, &mut downloaded, |_| {})
            .await
            .expect_err("premature EOF");
        assert!(matches!(error, SftpChannelError::RemoteStatus { code: 1 }));
        connection.disconnect().await.expect("disconnect client");

        let (connection, mut session) = transfer_session(b"abc".to_vec(), Some(0), false).await;
        let mut downloaded = Vec::new();
        let error = session
            .download_to(b"h", 0, None, 2, 2, &mut downloaded, |_| {})
            .await
            .expect_err("empty data");
        assert!(matches!(
            error,
            SftpChannelError::Protocol(SftpError::Malformed("empty read response"))
        ));
        connection.disconnect().await.expect("disconnect client");
    }

    #[tokio::test]
    async fn opens_subsystem_negotiates_v3_and_round_trips_packets() {
        let mut server_config = russh::server::Config::default();
        server_config.keys.push(
            PrivateKey::random(
                &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
                Algorithm::Ed25519,
            )
            .expect("server key"),
        );
        let server_config = Arc::new(server_config);
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind server");
        let address = listener.local_addr().expect("server address");
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept client");
            let _ = russh::server::run_stream(
                server_config,
                stream,
                SftpServer {
                    buffer: Vec::new(),
                    file: Vec::new(),
                    advertise_limits: true,
                    advertise_statvfs: true,
                    fsync_handle_open: Some(false),
                    read_reply_limit: None,
                    reorder_first_reads: false,
                    deferred_read_response: None,
                },
            )
            .await;
        });

        let verifier = |_host: &str, _key: &HostKey| Ok(());
        let config = ClientConfig::new("127.0.0.1", address.port(), verifier).expect("config");
        let mut connection = ClientConnection::connect(config).await.expect("connect client");
        connection.authenticate_password("user", b"password").await.expect("authenticate client");
        let mut session = SftpSession::open(&connection, 2).await.expect("open sftp session");
        assert_eq!(session.extensions().len(), 3);
        assert!(session.limits().is_some());
        assert_eq!(
            session.request_limits().await.expect("request limits"),
            Some(SftpLimits {
                max_packet_length: 256 * 1024,
                max_read_length: 128 * 1024,
                max_write_length: 64 * 1024,
                max_open_handles: 128,
            })
        );
        let request = session.client_mut().realpath(b".").expect("realpath request");
        session.send_request(&request).await.expect("write realpath");
        assert!(matches!(
            session.read_response().await.expect("read realpath"),
            SftpPacket::Name { id: 2, entries } if entries[0].filename == b"/srv"
        ));
        let statvfs = session.client_mut().statvfs(b".").expect("statvfs request");
        session.send_request(&statvfs).await.expect("send statvfs");
        let stats =
            session.read_response().await.expect("read statvfs").statvfs_response().unwrap();
        assert_eq!(stats.block_size, 4096);
        assert_eq!(stats.name_max, 255);
        assert_eq!(session.pending_requests(), 0);

        let open = session
            .client_mut()
            .open(b"file", 0x1a, SftpAttributes::default())
            .expect("open request");
        session.send_request(&open).await.expect("send open");
        let handle = match session.read_response().await.expect("read open") {
            SftpPacket::Handle { handle, .. } => handle,
            other => panic!("unexpected open response: {other:?}"),
        };
        let fsync = session.client_mut().fsync(handle.clone()).expect("fsync request");
        session.send_request(&fsync).await.expect("send fsync");
        assert!(matches!(
            session.read_response().await.expect("read fsync"),
            SftpPacket::Status { code: 0, .. }
        ));
        assert_eq!(session.pending_requests(), 0);
        let close = session.client_mut().close(handle.clone()).expect("close request");
        session.send_request(&close).await.expect("send close");
        assert!(matches!(
            session.read_response().await.expect("read close"),
            SftpPacket::Status { code: 0, .. }
        ));
        let closed_fsync = session.client_mut().fsync(handle).expect("closed fsync request");
        session.send_request(&closed_fsync).await.expect("send closed fsync");
        assert!(matches!(
            session.read_response().await.expect("read closed fsync"),
            SftpPacket::Status { code: 4, .. }
        ));
        assert_eq!(session.pending_requests(), 0);

        let missing = session.client_mut().statvfs(b"missing").expect("missing statvfs request");
        session.send_request(&missing).await.expect("send missing statvfs");
        assert!(matches!(
            session.read_response().await.expect("read missing statvfs"),
            SftpPacket::Status { code: 2, .. }
        ));
        assert_eq!(session.pending_requests(), 0);
        connection.disconnect().await.expect("disconnect client");
    }

    #[tokio::test]
    async fn session_pipelines_bounded_requests_and_releases_responses() {
        let mut server_config = russh::server::Config::default();
        server_config.keys.push(
            PrivateKey::random(
                &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
                Algorithm::Ed25519,
            )
            .expect("server key"),
        );
        let server_config = Arc::new(server_config);
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind server");
        let address = listener.local_addr().expect("server address");
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept client");
            let _ = russh::server::run_stream(
                server_config,
                stream,
                SftpServer {
                    buffer: Vec::new(),
                    file: Vec::new(),
                    advertise_limits: false,
                    advertise_statvfs: false,
                    fsync_handle_open: None,
                    read_reply_limit: None,
                    reorder_first_reads: false,
                    deferred_read_response: None,
                },
            )
            .await;
        });

        let verifier = |_host: &str, _key: &HostKey| Ok(());
        let config = ClientConfig::new("127.0.0.1", address.port(), verifier).expect("config");
        let mut connection = ClientConnection::connect(config).await.expect("connect client");
        connection.authenticate_password("user", b"password").await.expect("authenticate client");
        let mut session = SftpSession::open(&connection, 2).await.expect("open sftp session");
        assert_eq!(session.request_limits().await.expect("limits absence"), None);
        let first = session.client_mut().realpath(b"/first").expect("first request");
        let second = session.client_mut().realpath(b"/second").expect("second request");
        assert!(matches!(
            session.client_mut().realpath(b"/third"),
            Err(SftpError::OutstandingLimit)
        ));
        session.send_request(&first).await.expect("send first");
        session.send_request(&second).await.expect("send second");
        assert_eq!(session.pending_requests(), 2);
        assert!(matches!(
            session.read_response().await.expect("first response"),
            SftpPacket::Name { id: 1, .. }
        ));
        assert!(matches!(
            session.read_response().await.expect("second response"),
            SftpPacket::Name { id: 2, .. }
        ));
        assert_eq!(session.pending_requests(), 0);
        connection.disconnect().await.expect("disconnect client");
    }

    #[tokio::test]
    async fn transfer_helpers_resume_and_report_contiguous_progress() {
        let mut server_config = russh::server::Config::default();
        server_config.keys.push(
            PrivateKey::random(
                &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
                Algorithm::Ed25519,
            )
            .expect("server key"),
        );
        let server_config = Arc::new(server_config);
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind server");
        let address = listener.local_addr().expect("server address");
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept client");
            let _ = russh::server::run_stream(
                server_config,
                stream,
                SftpServer {
                    buffer: Vec::new(),
                    file: b"abcdef".to_vec(),
                    advertise_limits: false,
                    advertise_statvfs: false,
                    fsync_handle_open: None,
                    read_reply_limit: None,
                    reorder_first_reads: false,
                    deferred_read_response: None,
                },
            )
            .await;
        });

        let verifier = |_host: &str, _key: &HostKey| Ok(());
        let config = ClientConfig::new("127.0.0.1", address.port(), verifier).expect("config");
        let mut connection = ClientConnection::connect(config).await.expect("connect client");
        connection.authenticate_password("user", b"password").await.expect("authenticate client");
        let mut session = SftpSession::open(&connection, 2).await.expect("open sftp session");

        let mut downloaded = Vec::new();
        let mut download_progress = Vec::new();
        let count = session
            .download_to(b"h", 2, Some(6), 2, 2, &mut downloaded, |event| {
                download_progress.push(event);
            })
            .await
            .expect("download");
        assert_eq!(count, 4);
        assert_eq!(downloaded, b"cdef");
        assert_eq!(download_progress.last().unwrap().offset, 6);
        assert_eq!(download_progress.last().unwrap().transferred, 4);

        let mut upload_progress = Vec::new();
        let count = session
            .upload(b"h", 6, b"ghij", 2, 2, |event| upload_progress.push(event))
            .await
            .expect("upload");
        assert_eq!(count, 4);
        assert_eq!(upload_progress.last().unwrap().offset, 10);
        assert_eq!(upload_progress.last().unwrap().transferred, 4);
        connection.disconnect().await.expect("disconnect client");
    }
}
