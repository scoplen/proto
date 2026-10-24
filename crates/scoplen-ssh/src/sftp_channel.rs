//! Bounded SFTP v3 framing over one authenticated SSH session channel.

use std::{
    collections::{BTreeMap, VecDeque},
    io,
};

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    ChannelEvent, ClientChannelStream, ClientConnection, ClientError, MAX_SFTP_PACKET, SftpClient,
    SftpError, SftpExtension, SftpLimits, SftpPacket,
};

const LIMITS_EXTENSION: &[u8] = b"limits@openssh.com";
const WRITE_PACKET_FIXED_BYTES: usize = 4 + 1 + 4 + 4 + 8 + 4;

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
    /// An earlier exchange lost request/response correlation on this SFTP channel.
    #[error("SFTP session is unusable; open a new SFTP channel")]
    SessionUnusable,
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
    channel: Option<SftpChannel>,
    client: SftpClient,
    limits: Option<SftpLimits>,
}

struct ActiveExchange<'a> {
    session: &'a mut SftpSession,
    complete: bool,
}

impl<'a> ActiveExchange<'a> {
    fn new(session: &'a mut SftpSession) -> Self {
        Self { session, complete: false }
    }

    fn complete(&mut self) {
        self.complete = true;
    }
}

impl Drop for ActiveExchange<'_> {
    fn drop(&mut self) {
        if !self.complete {
            self.session.invalidate();
        }
    }
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
        let mut session = Self { channel: Some(channel), client, limits: None };
        session.limits = session.request_limits().await?;
        Ok(session)
    }

    /// Return the bounded extensions advertised by the server.
    #[must_use]
    pub fn extensions(&self) -> &[SftpExtension] {
        self.channel.as_ref().map_or(&[], SftpChannel::extensions)
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
        self.ensure_usable()?;
        if self.limits.is_some() {
            return Ok(self.limits);
        }
        if !self.extensions().iter().any(|extension| extension.name == LIMITS_EXTENSION) {
            self.limits = None;
            return Ok(None);
        }
        let request = self.client.request_limits()?;
        let mut exchange = ActiveExchange::new(self);
        exchange.session.send_request(&request).await?;
        let response = exchange.session.read_response().await?;
        let limits = response.limits_response()?;
        exchange.session.limits = Some(limits);
        exchange.complete();
        Ok(Some(limits))
    }

    fn ensure_usable(&self) -> Result<(), SftpChannelError> {
        if self.channel.is_some() { Ok(()) } else { Err(SftpChannelError::SessionUnusable) }
    }

    fn channel_mut(&mut self) -> Result<&mut SftpChannel, SftpChannelError> {
        self.channel.as_mut().ok_or(SftpChannelError::SessionUnusable)
    }

    fn invalidate(&mut self) {
        self.client.clear_pending();
        // russh closes the channel on drop; no close wait can hold the parent connection.
        drop(self.channel.take());
    }

    /// Send a request previously built by [`Self::client_mut`].
    ///
    /// # Errors
    ///
    /// Returns an error when the packet does not refer to a request tracked by this session or
    /// the channel cannot write it. A failed or canceled in-progress write invalidates this SFTP
    /// session; local packet rejection before dispatch leaves it usable.
    pub async fn send_request(&mut self, packet: &SftpPacket) -> Result<(), SftpChannelError> {
        self.ensure_usable()?;
        let Some(id) = packet.request_id() else {
            return Err(SftpError::Malformed("request has no request id").into());
        };
        if !self.client.tracks_request(id) {
            return Err(SftpError::UnknownRequest.into());
        }
        let frame = match packet.encode() {
            Ok(frame) => frame,
            Err(error) => {
                self.client.release_request(id);
                return Err(error.into());
            }
        };
        let mut exchange = ActiveExchange::new(self);
        exchange.session.channel_mut()?.write_frame(&frame).await?;
        exchange.complete();
        Ok(())
    }

    /// Read and correlate one response, releasing its pipeline slot.
    ///
    /// # Errors
    ///
    /// Returns an error when the channel ends, the packet is malformed, or its request id is not
    /// currently pending. A failed or canceled response read invalidates this SFTP session.
    pub async fn read_response(&mut self) -> Result<SftpPacket, SftpChannelError> {
        self.ensure_usable()?;
        let mut exchange = ActiveExchange::new(self);
        let packet = exchange.session.channel_mut()?.read_packet().await?;
        exchange.session.client.accept_response(&packet)?;
        exchange.complete();
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
    /// or sink I/O. A failed or canceled active transfer invalidates this SFTP session, except a
    /// fully correlated remote-status rejection with no pending responses. Local validation before
    /// dispatch leaves it usable.
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
        self.ensure_usable()?;
        if total.is_some_and(|end| end < start_offset) {
            return Err(SftpError::InvalidValue("transfer range").into());
        }
        let chunk_size = effective_chunk_size(chunk_size, self.limits, true)?;
        validate_transfer(handle, chunk_size, pipeline, self.pending_requests())?;
        let mut exchange = ActiveExchange::new(self);
        let result = exchange
            .session
            .download_to_inner(handle, start_offset, total, chunk_size, pipeline, sink, progress)
            .await;
        if result.is_ok()
            || (matches!(result, Err(SftpChannelError::RemoteStatus { .. }))
                && exchange.session.pending_requests() == 0)
        {
            exchange.complete();
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
    /// resume a local source by slicing it at the matching offset. Progress advances only after
    /// a contiguous prefix of successful write responses.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid bounds, failed writes, malformed responses, or a non-zero
    /// remote status. A failed or canceled active transfer invalidates this SFTP session, except a
    /// fully correlated remote-status rejection with no pending responses. Local validation before
    /// dispatch leaves it usable.
    pub async fn upload(
        &mut self,
        handle: &[u8],
        start_offset: u64,
        data: &[u8],
        chunk_size: u32,
        pipeline: usize,
        progress: impl FnMut(SftpTransferProgress),
    ) -> Result<u64, SftpChannelError> {
        let length =
            u64::try_from(data.len()).map_err(|_| SftpError::InvalidValue("transfer length"))?;
        let mut source = data;
        self.upload_from(handle, start_offset, length, chunk_size, pipeline, &mut source, progress)
            .await
    }

    /// Upload exactly `length` bytes from the reader's current position to a remote handle.
    ///
    /// The caller positions `source` for a resumed transfer. This method does not seek or read
    /// beyond `length`; a zero-length upload does not read the source or send writes. Progress
    /// advances only through the contiguous acknowledged prefix.
    ///
    /// # Errors
    ///
    /// Invalid bounds fail before reading or dispatch. Premature source EOF returns an I/O error
    /// with `UnexpectedEof`; other source errors retain their kind. A failed or canceled active
    /// transfer invalidates this SFTP session, except a fully correlated remote-status rejection
    /// with no pending responses.
    #[allow(clippy::too_many_arguments)]
    pub async fn upload_from<R, F>(
        &mut self,
        handle: &[u8],
        start_offset: u64,
        length: u64,
        chunk_size: u32,
        pipeline: usize,
        source: &mut R,
        progress: F,
    ) -> Result<u64, SftpChannelError>
    where
        R: AsyncRead + Unpin,
        F: FnMut(SftpTransferProgress),
    {
        self.ensure_usable()?;
        start_offset.checked_add(length).ok_or(SftpError::InvalidValue("transfer length"))?;
        let chunk_size = effective_upload_chunk_size(chunk_size, self.limits, handle.len())?;
        validate_transfer(handle, chunk_size, pipeline, self.pending_requests())?;
        let mut exchange = ActiveExchange::new(self);
        let result = exchange
            .session
            .upload_inner(handle, start_offset, length, chunk_size, pipeline, source, progress)
            .await;
        if result.is_ok()
            || (matches!(result, Err(SftpChannelError::RemoteStatus { .. }))
                && exchange.session.pending_requests() == 0)
        {
            exchange.complete();
        }
        result
    }

    #[allow(clippy::too_many_arguments)]
    async fn upload_inner<R, F>(
        &mut self,
        handle: &[u8],
        start_offset: u64,
        length: u64,
        chunk_size: u32,
        pipeline: usize,
        source: &mut R,
        mut progress: F,
    ) -> Result<u64, SftpChannelError>
    where
        R: AsyncRead + Unpin,
        F: FnMut(SftpTransferProgress),
    {
        let total = start_offset + length;
        let mut next = 0_u64;
        let mut transferred = 0_u64;
        let mut committed_offset = start_offset;
        let mut inflight = BTreeMap::<u32, (u64, usize)>::new();
        let mut completed = BTreeMap::<u64, usize>::new();
        let mut chunk = vec![0_u8; chunk_size as usize];
        progress(SftpTransferProgress { offset: start_offset, transferred, total: Some(total) });

        loop {
            while next < length
                && inflight.len() + completed.len() < pipeline
                && self.client.available_requests() > 0
            {
                let chunk_len = usize::try_from((length - next).min(u64::from(chunk_size)))
                    .map_err(|_| SftpError::InvalidValue("transfer chunk size"))?;
                source.read_exact(&mut chunk[..chunk_len]).await?;
                let offset = start_offset + next;
                let request =
                    self.client.write(handle.to_vec(), offset, chunk[..chunk_len].to_vec())?;
                let id = request.request_id().ok_or(SftpError::Malformed("write request id"))?;
                self.send_request(&request).await?;
                inflight.insert(id, (offset, chunk_len));
                next += chunk_len as u64;
            }
            if inflight.is_empty() {
                if next != length || !completed.is_empty() {
                    return Err(SftpError::Malformed("non-contiguous write responses").into());
                }
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

fn effective_upload_chunk_size(
    requested: u32,
    limits: Option<SftpLimits>,
    handle_len: usize,
) -> Result<u32, SftpChannelError> {
    let overhead = WRITE_PACKET_FIXED_BYTES.saturating_add(handle_len);
    let local_data_limit = MAX_SFTP_PACKET - 64;
    let local_packet_limit = MAX_SFTP_PACKET.saturating_sub(overhead);
    let peer_limit = limits.map_or(u64::MAX, |limits| {
        limits.max_write_length.min(limits.max_packet_length.saturating_sub(overhead as u64))
    });
    let bounded = u64::from(requested)
        .min(local_data_limit as u64)
        .min(local_packet_limit as u64)
        .min(peer_limit);
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
        self.write_frame(&frame).await
    }

    async fn write_frame(&mut self, frame: &[u8]) -> Result<(), SftpChannelError> {
        self.stream.write_all(frame).await?;
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
    use std::{
        pin::Pin,
        sync::Arc,
        task::{Context, Poll},
    };

    use russh::keys::PrivateKey;
    use ssh_key::Algorithm;
    use tokio::{io::ReadBuf, net::TcpListener, sync::oneshot};

    use super::*;
    use crate::{ClientConfig, HostKey, SftpAttributes, SftpNameEntry, SftpStatvfs};

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum RenamePhase {
        Original,
        Renamed,
        Replaced,
        Removed,
    }

    #[derive(Clone, Copy, Default)]
    enum WriteAckMode {
        #[default]
        Normal,
        ReorderFirstTwo,
        HoldFirst,
    }

    struct TestReader<'a> {
        bytes: &'a [u8],
        position: usize,
        fail_at: Option<usize>,
    }

    impl AsyncRead for TestReader<'_> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.fail_at.is_some_and(|at| self.position >= at) {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "source failed",
                )));
            }
            let remaining = &self.bytes[self.position..];
            let count = remaining.len().min(buffer.remaining());
            buffer.put_slice(&remaining[..count]);
            self.position += count;
            Poll::Ready(Ok(()))
        }
    }

    #[derive(Default, PartialEq, Eq)]
    enum DirectoryState {
        #[default]
        Missing,
        Empty,
        Nonempty,
    }

    #[derive(Default)]
    struct DirectoryFixture {
        state: DirectoryState,
        file_handle_open: bool,
        directory_handle_open: bool,
        entries_returned: bool,
    }

    impl DirectoryFixture {
        fn status(id: u32, code: u32) -> SftpPacket {
            SftpPacket::Status { id, code, message: Vec::new(), language: Vec::new() }
        }

        fn mkdir(&mut self, id: u32, path: &[u8]) -> SftpPacket {
            if path != b"dir" || self.state != DirectoryState::Missing {
                return Self::status(id, 4);
            }
            self.state = DirectoryState::Empty;
            Self::status(id, 0)
        }

        fn open_file(&mut self, id: u32, path: &[u8], pflags: u32) -> SftpPacket {
            if path != b"dir/entry" || pflags != 0x1a || self.state == DirectoryState::Missing {
                return Self::status(id, 2);
            }
            self.state = DirectoryState::Nonempty;
            self.file_handle_open = true;
            SftpPacket::Handle { id, handle: b"dir-file-h".to_vec() }
        }

        fn opendir(&mut self, id: u32, path: &[u8]) -> SftpPacket {
            if path != b"dir" || self.state == DirectoryState::Missing {
                return Self::status(id, 2);
            }
            self.directory_handle_open = true;
            self.entries_returned = false;
            SftpPacket::Handle { id, handle: b"dir-h".to_vec() }
        }

        fn readdir(&mut self, id: u32, handle: &[u8]) -> SftpPacket {
            if handle != b"dir-h" || !self.directory_handle_open {
                return Self::status(id, 4);
            }
            if self.entries_returned {
                return Self::status(id, 1);
            }
            self.entries_returned = true;
            SftpPacket::Name {
                id,
                entries: vec![
                    SftpNameEntry::new(b"entry", Vec::new(), SftpAttributes::default()).unwrap(),
                ],
            }
        }

        fn close(&mut self, id: u32, handle: &[u8]) -> SftpPacket {
            match handle {
                b"dir-file-h" if self.file_handle_open => self.file_handle_open = false,
                b"dir-h" if self.directory_handle_open => self.directory_handle_open = false,
                _ => return Self::status(id, 4),
            }
            Self::status(id, 0)
        }

        fn remove(&mut self, id: u32, path: &[u8]) -> SftpPacket {
            if path != b"dir/entry" || self.state != DirectoryState::Nonempty {
                return Self::status(id, 2);
            }
            self.state = DirectoryState::Empty;
            Self::status(id, 0)
        }

        fn rmdir(&mut self, id: u32, path: &[u8]) -> SftpPacket {
            if path != b"dir" || self.state == DirectoryState::Missing {
                return Self::status(id, 2);
            }
            if self.state == DirectoryState::Nonempty {
                return Self::status(id, 4);
            }
            self.state = DirectoryState::Missing;
            Self::status(id, 0)
        }
    }

    struct SftpServer {
        buffer: Vec<u8>,
        file: Vec<u8>,
        file_mtime: Option<u32>,
        advertise_limits: bool,
        advertise_statvfs: bool,
        extension_handle_open: Option<bool>,
        hardlink_created: Option<bool>,
        rename_phase: Option<RenamePhase>,
        expand_path_prefix: Option<&'static [u8]>,
        copy_data_target: Option<Vec<u8>>,
        lsetstat_link_mtime: Option<u32>,
        symlink_target: Option<Vec<u8>>,
        directory: Option<DirectoryFixture>,
        read_reply_limit: Option<usize>,
        reorder_first_reads: bool,
        deferred_read_response: Option<SftpPacket>,
        write_ack_mode: WriteAckMode,
        deferred_write_response: Option<SftpPacket>,
        outbound_window_signal: Option<oneshot::Sender<()>>,
    }

    impl SftpServer {
        fn directory_response(&mut self, packet: &SftpPacket) -> Option<SftpPacket> {
            let directory = self.directory.as_mut()?;
            match packet {
                SftpPacket::Mkdir { id, path, .. } => Some(directory.mkdir(*id, path)),
                SftpPacket::Open { id, path, pflags, .. } if path == b"dir/entry" => {
                    Some(directory.open_file(*id, path, *pflags))
                }
                SftpPacket::Opendir { id, path } => Some(directory.opendir(*id, path)),
                SftpPacket::Readdir { id, handle } => Some(directory.readdir(*id, handle)),
                SftpPacket::Close { id, handle }
                    if handle == b"dir-h" || handle == b"dir-file-h" =>
                {
                    Some(directory.close(*id, handle))
                }
                SftpPacket::Remove { id, path } if path == b"dir/entry" => {
                    Some(directory.remove(*id, path))
                }
                SftpPacket::Rmdir { id, path } => Some(directory.rmdir(*id, path)),
                _ => None,
            }
        }

        fn version_response(&self) -> SftpPacket {
            let mut extensions = Vec::new();
            if self.advertise_limits {
                extensions.push(SftpExtension::new(b"limits@openssh.com", b"1").unwrap());
            }
            if self.advertise_statvfs {
                extensions.push(SftpExtension::new(b"statvfs@openssh.com", b"2").unwrap());
            }
            if self.extension_handle_open.is_some() {
                extensions.push(SftpExtension::new(b"fsync@openssh.com", b"1").unwrap());
                extensions.push(SftpExtension::new(b"fstatvfs@openssh.com", b"2").unwrap());
            }
            if self.hardlink_created.is_some() {
                extensions.push(SftpExtension::new(b"hardlink@openssh.com", b"1").unwrap());
            }
            if self.rename_phase.is_some() {
                extensions.push(SftpExtension::new(b"posix-rename@openssh.com", b"1").unwrap());
            }
            if self.expand_path_prefix.is_some() {
                extensions.push(SftpExtension::new(b"expand-path@openssh.com", b"1").unwrap());
            }
            if self.copy_data_target.is_some() {
                extensions.push(SftpExtension::new(b"copy-data", b"1").unwrap());
            }
            if self.lsetstat_link_mtime.is_some() {
                extensions.push(SftpExtension::new(b"lsetstat@openssh.com", b"1").unwrap());
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

        fn filesystem_stats(id: u32) -> SftpPacket {
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
        }

        fn statvfs_response(id: u32, data: &[u8]) -> SftpPacket {
            if data == b"\0\0\0\x01." {
                Self::filesystem_stats(id)
            } else {
                SftpPacket::Status { id, code: 2, message: Vec::new(), language: Vec::new() }
            }
        }

        fn open_extension_handle(&mut self, id: u32) -> SftpPacket {
            self.extension_handle_open = Some(true);
            SftpPacket::Handle { id, handle: b"h".to_vec() }
        }

        fn open_response(&mut self, id: u32, path: &[u8]) -> SftpPacket {
            if path == b"copy-target" && self.copy_data_target.is_some() {
                self.extension_handle_open = Some(true);
                SftpPacket::Handle { id, handle: b"copy".to_vec() }
            } else if path == b"replacement"
                && matches!(self.rename_phase, Some(RenamePhase::Original | RenamePhase::Renamed))
            {
                self.extension_handle_open = Some(true);
                SftpPacket::Handle { id, handle: b"old".to_vec() }
            } else if ((path == b"file" || path == b"/srv/file")
                && !matches!(
                    self.rename_phase,
                    Some(RenamePhase::Renamed | RenamePhase::Replaced | RenamePhase::Removed)
                ))
                || (path == b"link" && self.hardlink_created == Some(true))
                || (path == b"renamed" && self.rename_phase == Some(RenamePhase::Renamed))
                || (path == b"replacement" && self.rename_phase == Some(RenamePhase::Replaced))
            {
                self.open_extension_handle(id)
            } else {
                SftpPacket::Status { id, code: 2, message: Vec::new(), language: Vec::new() }
            }
        }

        fn close_extension_handle(&mut self, id: u32, handle: &[u8]) -> SftpPacket {
            let code = if (handle == b"h" || handle == b"old" || handle == b"copy")
                && self.extension_handle_open == Some(true)
            {
                self.extension_handle_open = Some(false);
                0
            } else {
                4
            };
            SftpPacket::Status { id, code, message: Vec::new(), language: Vec::new() }
        }

        fn fsync_response(&self, id: u32, data: &[u8]) -> SftpPacket {
            let code = if data == b"\0\0\0\x01h" && self.extension_handle_open == Some(true) {
                0
            } else {
                4
            };
            SftpPacket::Status { id, code, message: Vec::new(), language: Vec::new() }
        }

        fn fstatvfs_response(&self, id: u32, data: &[u8]) -> SftpPacket {
            if data == b"\0\0\0\x01h" && self.extension_handle_open == Some(true) {
                Self::filesystem_stats(id)
            } else {
                SftpPacket::Status { id, code: 4, message: Vec::new(), language: Vec::new() }
            }
        }

        fn fsetstat_response(
            &mut self,
            id: u32,
            handle: &[u8],
            attrs: &SftpAttributes,
        ) -> SftpPacket {
            let code = if handle == b"h" && self.extension_handle_open == Some(true) {
                match attrs.size.and_then(|size| usize::try_from(size).ok()) {
                    Some(size) if size <= 1024 * 1024 => {
                        self.file.resize(size, 0);
                        0
                    }
                    _ => 4,
                }
            } else {
                4
            };
            SftpPacket::Status { id, code, message: Vec::new(), language: Vec::new() }
        }

        fn setstat_response(&mut self, id: u32, path: &[u8], attrs: &SftpAttributes) -> SftpPacket {
            let size = attrs.size.and_then(|size| usize::try_from(size).ok());
            let code = if path != b"file" || self.rename_phase != Some(RenamePhase::Original) {
                2
            } else if attrs.size.is_some() && size.is_none_or(|size| size > 1024 * 1024) {
                4
            } else {
                if let Some(size) = size {
                    self.file.resize(size, 0);
                }
                if let Some(mtime) = attrs.modify_time {
                    self.file_mtime = Some(mtime);
                }
                0
            };
            SftpPacket::Status { id, code, message: Vec::new(), language: Vec::new() }
        }

        fn copy_data_response(&mut self, id: u32, data: &[u8]) -> SftpPacket {
            let expected = SftpPacket::copy_data_request(id, b"h", 2, 4, b"copy", 1).unwrap();
            let code = if self.extension_handle_open == Some(true)
                && matches!(expected, SftpPacket::Extended { data: expected, .. } if data == expected)
            {
                let target = self.copy_data_target.as_mut().unwrap();
                target[1..5].copy_from_slice(&self.file[2..6]);
                0
            } else {
                4
            };
            SftpPacket::Status { id, code, message: Vec::new(), language: Vec::new() }
        }

        fn lsetstat_response(&mut self, id: u32, data: &[u8]) -> SftpPacket {
            let attrs = SftpAttributes {
                access_time: Some(1_600_000_000),
                modify_time: Some(1_600_000_000),
                ..SftpAttributes::default()
            };
            let expected = SftpPacket::lsetstat_request(id, b"symlink", &attrs).unwrap();
            let missing = SftpPacket::lsetstat_request(id, b"missing", &attrs).unwrap();
            let code = if matches!(expected, SftpPacket::Extended { data: expected, .. } if data == expected)
            {
                if self.symlink_target.is_some() {
                    self.lsetstat_link_mtime = Some(1_600_000_000);
                    0
                } else {
                    2
                }
            } else if matches!(missing, SftpPacket::Extended { data: missing, .. } if data == missing)
            {
                2
            } else {
                4
            };
            SftpPacket::Status { id, code, message: Vec::new(), language: Vec::new() }
        }

        fn link_attributes(&self, id: u32, follow: bool, path: &[u8]) -> SftpPacket {
            if path != b"symlink" || self.symlink_target.is_none() {
                return SftpPacket::Status {
                    id,
                    code: 2,
                    message: Vec::new(),
                    language: Vec::new(),
                };
            }
            let mtime = if follow {
                self.file_mtime.unwrap_or(1_700_000_000)
            } else {
                self.lsetstat_link_mtime.unwrap()
            };
            SftpPacket::Attrs {
                id,
                attrs: SftpAttributes {
                    access_time: Some(mtime),
                    modify_time: Some(mtime),
                    ..SftpAttributes::default()
                },
            }
        }

        fn symlink_response(
            &mut self,
            id: u32,
            link_path: &[u8],
            target_path: &[u8],
        ) -> SftpPacket {
            let code = if link_path == b"symlink"
                && target_path == b"file"
                && self.symlink_target.is_none()
            {
                self.symlink_target = Some(target_path.to_vec());
                0
            } else {
                4
            };
            SftpPacket::Status { id, code, message: Vec::new(), language: Vec::new() }
        }

        fn readlink_response(&self, id: u32, path: &[u8]) -> SftpPacket {
            if let Some(target) = self.symlink_target.as_ref().filter(|_| path == b"symlink") {
                return SftpPacket::Name {
                    id,
                    entries: vec![
                        SftpNameEntry::new(target.clone(), Vec::new(), SftpAttributes::default())
                            .unwrap(),
                    ],
                };
            }
            SftpPacket::Status { id, code: 2, message: Vec::new(), language: Vec::new() }
        }

        fn remove_symlink(&mut self, id: u32, path: &[u8]) -> SftpPacket {
            let code =
                if path == b"symlink" && self.symlink_target.take().is_some() { 0 } else { 2 };
            SftpPacket::Status { id, code, message: Vec::new(), language: Vec::new() }
        }

        fn hardlink_response(&mut self, id: u32, data: &[u8]) -> SftpPacket {
            let code = if data == b"\0\0\0\x07missing\0\0\0\x0cmissing-link" {
                2
            } else if data == b"\0\0\0\x04file\0\0\0\x04link"
                && self.hardlink_created == Some(false)
            {
                self.hardlink_created = Some(true);
                0
            } else {
                4
            };
            SftpPacket::Status { id, code, message: Vec::new(), language: Vec::new() }
        }

        fn remove_extension_file(&mut self, id: u32, path: &[u8]) -> SftpPacket {
            let code = if path == b"link" && self.hardlink_created == Some(true) {
                self.hardlink_created = Some(false);
                0
            } else if path == b"replacement" && self.rename_phase == Some(RenamePhase::Replaced) {
                self.rename_phase = Some(RenamePhase::Removed);
                0
            } else {
                2
            };
            SftpPacket::Status { id, code, message: Vec::new(), language: Vec::new() }
        }

        fn rename_response(&mut self, id: u32, data: &[u8]) -> SftpPacket {
            let code = if data == b"\0\0\0\x07missing\0\0\0\x0fmissing-renamed" {
                2
            } else if data == b"\0\0\0\x04file\0\0\0\x07renamed"
                && self.rename_phase == Some(RenamePhase::Original)
            {
                self.rename_phase = Some(RenamePhase::Renamed);
                0
            } else if data == b"\0\0\0\x07renamed\0\0\0\x0breplacement"
                && self.rename_phase == Some(RenamePhase::Renamed)
            {
                self.rename_phase = Some(RenamePhase::Replaced);
                0
            } else {
                4
            };
            SftpPacket::Status { id, code, message: Vec::new(), language: Vec::new() }
        }

        fn standard_rename_response(
            &mut self,
            id: u32,
            old_path: &[u8],
            new_path: &[u8],
        ) -> SftpPacket {
            let code = match (old_path, new_path, self.rename_phase) {
                (b"missing", b"missing-renamed", _) => 2,
                (b"file", b"renamed", Some(RenamePhase::Original)) => {
                    self.rename_phase = Some(RenamePhase::Renamed);
                    0
                }
                (b"renamed", b"file", Some(RenamePhase::Renamed)) => {
                    self.rename_phase = Some(RenamePhase::Original);
                    0
                }
                _ => 4,
            };
            SftpPacket::Status { id, code, message: Vec::new(), language: Vec::new() }
        }

        fn expand_path_response(&self, id: u32, data: &[u8]) -> SftpPacket {
            let leaf: &[u8] = if data == b"\0\0\0\x04file" {
                b"file"
            } else if data == b"\0\0\0\x07missing" {
                b"missing"
            } else {
                return SftpPacket::Status {
                    id,
                    code: 4,
                    message: Vec::new(),
                    language: Vec::new(),
                };
            };
            SftpPacket::Name {
                id,
                entries: vec![
                    SftpNameEntry::new(
                        [self.expand_path_prefix.unwrap(), leaf].concat(),
                        Vec::new(),
                        SftpAttributes::default(),
                    )
                    .unwrap(),
                ],
            }
        }

        fn extension_response(&mut self, id: u32, name: &[u8], data: &[u8]) -> Option<SftpPacket> {
            if name == b"limits@openssh.com" && self.advertise_limits {
                Some(Self::limits_response(id))
            } else if name == b"statvfs@openssh.com" && self.advertise_statvfs {
                Some(Self::statvfs_response(id, data))
            } else if name == b"fsync@openssh.com" && self.extension_handle_open.is_some() {
                Some(self.fsync_response(id, data))
            } else if name == b"fstatvfs@openssh.com" && self.extension_handle_open.is_some() {
                Some(self.fstatvfs_response(id, data))
            } else if name == b"hardlink@openssh.com" && self.hardlink_created.is_some() {
                Some(self.hardlink_response(id, data))
            } else if name == b"posix-rename@openssh.com" && self.rename_phase.is_some() {
                Some(self.rename_response(id, data))
            } else if name == b"expand-path@openssh.com" && self.expand_path_prefix.is_some() {
                Some(self.expand_path_response(id, data))
            } else if name == b"copy-data" && self.copy_data_target.is_some() {
                Some(self.copy_data_response(id, data))
            } else if name == b"lsetstat@openssh.com" && self.lsetstat_link_mtime.is_some() {
                Some(self.lsetstat_response(id, data))
            } else {
                None
            }
        }

        fn read_response(&self, id: u32, handle: &[u8], offset: u64, length: u32) -> SftpPacket {
            if self.extension_handle_open.is_some() && self.extension_handle_open != Some(true) {
                return SftpPacket::Status {
                    id,
                    code: 4,
                    message: Vec::new(),
                    language: Vec::new(),
                };
            }
            let contents: &[u8] = if handle == b"copy" {
                self.copy_data_target.as_deref().unwrap_or_default()
            } else if handle == b"old"
                && matches!(self.rename_phase, Some(RenamePhase::Original | RenamePhase::Renamed))
            {
                b"previous destination contents"
            } else if handle == b"h" || self.extension_handle_open.is_none() {
                &self.file
            } else {
                return SftpPacket::Status {
                    id,
                    code: 4,
                    message: Vec::new(),
                    language: Vec::new(),
                };
            };
            match usize::try_from(offset) {
                Ok(start) if start < contents.len() => {
                    let end = start
                        .saturating_add(
                            self.read_reply_limit.unwrap_or(length as usize).min(length as usize),
                        )
                        .min(contents.len());
                    SftpPacket::Data { id, data: contents[start..end].to_vec() }
                }
                _ => SftpPacket::Status { id, code: 1, message: Vec::new(), language: Vec::new() },
            }
        }

        fn write_response(
            &mut self,
            id: u32,
            handle: &[u8],
            offset: u64,
            data: &[u8],
        ) -> Option<SftpPacket> {
            let code = if handle == b"reject" {
                4
            } else {
                let start = usize::try_from(offset).ok()?;
                let end = start.saturating_add(data.len());
                if end > self.file.len() {
                    self.file.resize(end, 0);
                }
                self.file[start..end].copy_from_slice(data);
                0
            };
            Some(SftpPacket::Status { id, code, message: Vec::new(), language: Vec::new() })
        }

        fn dispatch_write_ack(
            &mut self,
            response: &SftpPacket,
            channel: russh::ChannelId,
            session: &mut russh::server::Session,
        ) -> bool {
            match self.write_ack_mode {
                WriteAckMode::ReorderFirstTwo => {
                    if self.deferred_write_response.is_none() {
                        self.deferred_write_response = Some(response.clone());
                        return true;
                    }
                    self.write_ack_mode = WriteAckMode::Normal;
                    let _ = session.data(channel, response.encode().expect("SFTP response"));
                    let deferred = self.deferred_write_response.take().expect("deferred write");
                    let _ =
                        session.data(channel, deferred.encode().expect("deferred SFTP response"));
                    true
                }
                WriteAckMode::HoldFirst if self.deferred_write_response.is_none() => {
                    self.deferred_write_response = Some(response.clone());
                    true
                }
                WriteAckMode::Normal | WriteAckMode::HoldFirst => false,
            }
        }

        fn dispatch_read_response(
            &mut self,
            response: &SftpPacket,
            channel: russh::ChannelId,
            session: &mut russh::server::Session,
        ) -> bool {
            if !self.reorder_first_reads {
                return false;
            }
            if self.deferred_read_response.is_none() {
                self.deferred_read_response = Some(response.clone());
                return true;
            }
            self.reorder_first_reads = false;
            let _ = session.data(channel, response.encode().expect("SFTP response"));
            let deferred = self.deferred_read_response.take().expect("deferred read");
            let _ = session.data(channel, deferred.encode().expect("deferred SFTP response"));
            true
        }

        fn corrupt_read_response(
            packet: &SftpPacket,
            channel: russh::ChannelId,
            session: &mut russh::server::Session,
        ) -> bool {
            let SftpPacket::Read { handle, .. } = packet else { return false };
            if handle == b"malformed-wire" {
                let _ = session.data(channel, vec![0, 0, 0, 1, 0xff]);
                return true;
            }
            if handle == b"truncated-wire" {
                let _ = session.data(channel, vec![0, 0, 0, 8, 0x67]);
                let _ = session.close(channel);
                return true;
            }
            false
        }

        fn realpath_response(id: u32, path: &[u8]) -> SftpPacket {
            let resolved = match path {
                b"." => b"/srv".to_vec(),
                b"file" | b"./file" => b"/srv/file".to_vec(),
                b"missing" => b"/srv/missing".to_vec(),
                b"/first" | b"/second" => path.to_vec(),
                _ => {
                    return SftpPacket::Status {
                        id,
                        code: 2,
                        message: Vec::new(),
                        language: Vec::new(),
                    };
                }
            };
            SftpPacket::Name {
                id,
                entries: vec![
                    SftpNameEntry::new(resolved, Vec::new(), SftpAttributes::default()).unwrap(),
                ],
            }
        }

        fn path_or_metadata_response(&mut self, packet: &SftpPacket) -> Option<SftpPacket> {
            match packet {
                SftpPacket::Realpath { id, path } => Some(Self::realpath_response(*id, path)),
                SftpPacket::Stat { id, path }
                    if self.file_mtime.is_some()
                        && path == b"file"
                        && self.rename_phase == Some(RenamePhase::Original) =>
                {
                    Some(SftpPacket::Attrs {
                        id: *id,
                        attrs: SftpAttributes {
                            size: Some(self.file.len() as u64),
                            access_time: self.file_mtime,
                            modify_time: self.file_mtime,
                            ..SftpAttributes::default()
                        },
                    })
                }
                SftpPacket::Setstat { id, path, attrs } if self.file_mtime.is_some() => {
                    Some(self.setstat_response(*id, path, attrs))
                }
                SftpPacket::Rename { id, old_path, new_path } if self.rename_phase.is_some() => {
                    Some(self.standard_rename_response(*id, old_path, new_path))
                }
                SftpPacket::Fstat { id, handle } if self.extension_handle_open.is_some() => {
                    if handle == b"h" && self.extension_handle_open == Some(true) {
                        Some(SftpPacket::Attrs {
                            id: *id,
                            attrs: SftpAttributes {
                                size: Some(self.file.len() as u64),
                                ..SftpAttributes::default()
                            },
                        })
                    } else {
                        Some(SftpPacket::Status {
                            id: *id,
                            code: 4,
                            message: Vec::new(),
                            language: Vec::new(),
                        })
                    }
                }
                SftpPacket::Fsetstat { id, handle, attrs }
                    if self.extension_handle_open.is_some() =>
                {
                    Some(self.fsetstat_response(*id, handle, attrs))
                }
                _ => None,
            }
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

        fn adjust_window(&mut self, _channel: russh::ChannelId, current: u32) -> u32 {
            if let Some(signal) = self.outbound_window_signal.take() {
                let _ = signal.send(());
                1
            } else {
                current
            }
        }

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

        async fn channel_close(
            &mut self,
            _channel: russh::ChannelId,
            _session: &mut russh::server::Session,
        ) -> Result<(), Self::Error> {
            self.buffer.clear();
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
                if Self::corrupt_read_response(&packet, channel, session) {
                    continue;
                }
                let is_read = matches!(packet, SftpPacket::Read { .. });
                let is_write = matches!(packet, SftpPacket::Write { .. });
                let response = if let Some(response) = self
                    .directory_response(&packet)
                    .or_else(|| self.path_or_metadata_response(&packet))
                {
                    response
                } else {
                    match packet {
                        SftpPacket::Init { .. } => self.version_response(),
                        SftpPacket::Open { id, path, .. }
                            if self.extension_handle_open.is_some() =>
                        {
                            self.open_response(id, &path)
                        }
                        SftpPacket::Close { id, handle }
                            if self.extension_handle_open.is_some() =>
                        {
                            self.close_extension_handle(id, &handle)
                        }
                        SftpPacket::Lstat { id, path } if self.lsetstat_link_mtime.is_some() => {
                            self.link_attributes(id, false, &path)
                        }
                        SftpPacket::Stat { id, path } if self.lsetstat_link_mtime.is_some() => {
                            self.link_attributes(id, true, &path)
                        }
                        SftpPacket::Symlink { id, link_path, target_path }
                            if self.lsetstat_link_mtime.is_some() =>
                        {
                            self.symlink_response(id, &link_path, &target_path)
                        }
                        SftpPacket::Readlink { id, path } if self.lsetstat_link_mtime.is_some() => {
                            self.readlink_response(id, &path)
                        }
                        SftpPacket::Remove { id, path }
                            if self.lsetstat_link_mtime.is_some() && path == b"symlink" =>
                        {
                            self.remove_symlink(id, &path)
                        }
                        SftpPacket::Read { id, handle, offset, length } => {
                            self.read_response(id, &handle, offset, length)
                        }
                        SftpPacket::Remove { id, path }
                            if self.hardlink_created.is_some() || self.rename_phase.is_some() =>
                        {
                            self.remove_extension_file(id, &path)
                        }
                        SftpPacket::Write { id, handle, offset, data } => {
                            if handle == b"stall" || handle == b"close" {
                                if handle == b"close" {
                                    let _ = session.close(channel);
                                }
                                continue;
                            }
                            let Some(response) = self.write_response(id, &handle, offset, &data)
                            else {
                                return Ok(());
                            };
                            response
                        }
                        SftpPacket::Extended { id, name, data } => {
                            let Some(response) = self.extension_response(id, &name, &data) else {
                                continue;
                            };
                            response
                        }
                        _ => continue,
                    }
                };
                if is_read && self.dispatch_read_response(&response, channel, session) {
                    continue;
                }
                if is_write && self.dispatch_write_ack(&response, channel, session) {
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
        directory: bool,
    ) -> (ClientConnection, SftpSession) {
        transfer_session_with_outbound_window(
            file,
            read_reply_limit,
            reorder_first_reads,
            directory,
            None,
            WriteAckMode::Normal,
        )
        .await
    }

    async fn transfer_session_with_outbound_window(
        file: Vec<u8>,
        read_reply_limit: Option<usize>,
        reorder_first_reads: bool,
        directory: bool,
        outbound_window_signal: Option<oneshot::Sender<()>>,
        write_ack_mode: WriteAckMode,
    ) -> (ClientConnection, SftpSession) {
        let mut server_config = russh::server::Config::default();
        if outbound_window_signal.is_some() {
            server_config.window_size = 64;
            server_config.maximum_packet_size = 32;
        }
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
                    file_mtime: None,
                    advertise_limits: false,
                    advertise_statvfs: false,
                    extension_handle_open: None,
                    hardlink_created: None,
                    rename_phase: None,
                    expand_path_prefix: None,
                    copy_data_target: None,
                    lsetstat_link_mtime: None,
                    symlink_target: None,
                    directory: directory.then(DirectoryFixture::default),
                    read_reply_limit,
                    reorder_first_reads,
                    deferred_read_response: None,
                    write_ack_mode,
                    deferred_write_response: None,
                    outbound_window_signal,
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

    async fn directory_response(session: &mut SftpSession, request: SftpPacket) -> SftpPacket {
        session.send_request(&request).await.expect("send directory request");
        let response = session.read_response().await.expect("read directory response");
        assert_eq!(session.pending_requests(), 0);
        response
    }

    #[tokio::test]
    async fn directory_lifecycle_round_trips_over_authenticated_channel() {
        let (connection, mut session) = transfer_session(Vec::new(), None, false, true).await;
        let missing = session.client_mut().opendir(b"missing").unwrap();
        assert!(matches!(
            directory_response(&mut session, missing).await,
            SftpPacket::Status { code: 2, .. }
        ));

        let mkdir = session.client_mut().mkdir(b"dir", SftpAttributes::default()).unwrap();
        assert!(matches!(
            directory_response(&mut session, mkdir).await,
            SftpPacket::Status { code: 0, .. }
        ));
        let create =
            session.client_mut().open(b"dir/entry", 0x1a, SftpAttributes::default()).unwrap();
        let file_handle = match directory_response(&mut session, create).await {
            SftpPacket::Handle { handle, .. } => handle,
            other => panic!("unexpected file handle response: {other:?}"),
        };
        let close = session.client_mut().close(file_handle).unwrap();
        assert!(matches!(
            directory_response(&mut session, close).await,
            SftpPacket::Status { code: 0, .. }
        ));

        let open = session.client_mut().opendir(b"dir").unwrap();
        let directory_handle = match directory_response(&mut session, open).await {
            SftpPacket::Handle { handle, .. } => handle,
            other => panic!("unexpected directory handle response: {other:?}"),
        };
        let read = session.client_mut().readdir(directory_handle.clone()).unwrap();
        assert!(matches!(
            directory_response(&mut session, read).await,
            SftpPacket::Name { entries, .. }
                if entries.iter().any(|entry| entry.filename == b"entry")
        ));
        let eof = session.client_mut().readdir(directory_handle.clone()).unwrap();
        assert!(matches!(
            directory_response(&mut session, eof).await,
            SftpPacket::Status { code: 1, .. }
        ));
        let nonempty = session.client_mut().rmdir(b"dir").unwrap();
        assert!(matches!(
            directory_response(&mut session, nonempty).await,
            SftpPacket::Status { code: 4, .. }
        ));
        let close = session.client_mut().close(directory_handle.clone()).unwrap();
        assert!(matches!(
            directory_response(&mut session, close).await,
            SftpPacket::Status { code: 0, .. }
        ));
        let closed = session.client_mut().readdir(directory_handle).unwrap();
        assert!(matches!(
            directory_response(&mut session, closed).await,
            SftpPacket::Status { code: 4, .. }
        ));
        let remove = session.client_mut().remove(b"dir/entry").unwrap();
        assert!(matches!(
            directory_response(&mut session, remove).await,
            SftpPacket::Status { code: 0, .. }
        ));
        let rmdir = session.client_mut().rmdir(b"dir").unwrap();
        assert!(matches!(
            directory_response(&mut session, rmdir).await,
            SftpPacket::Status { code: 0, .. }
        ));
        let removed = session.client_mut().opendir(b"dir").unwrap();
        assert!(matches!(
            directory_response(&mut session, removed).await,
            SftpPacket::Status { code: 2, .. }
        ));
        connection.disconnect().await.expect("disconnect client");
    }

    #[tokio::test]
    async fn short_read_resumes_missing_ranges_before_completing_download() {
        let (connection, mut session) =
            transfer_session(b"abcdef".to_vec(), Some(1), true, false).await;
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
        let (connection, mut session) = transfer_session(b"abc".to_vec(), None, false, false).await;
        let mut downloaded = Vec::new();
        let error = session
            .download_to(b"h", 0, Some(6), 2, 2, &mut downloaded, |_| {})
            .await
            .expect_err("premature EOF");
        assert!(matches!(error, SftpChannelError::RemoteStatus { code: 1 }));
        connection.disconnect().await.expect("disconnect client");

        let (connection, mut session) =
            transfer_session(b"abc".to_vec(), Some(0), false, false).await;
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
    async fn failed_pipelined_download_does_not_accept_new_work_on_stale_channel() {
        let (connection, mut session) =
            transfer_session(b"abc".to_vec(), Some(0), false, false).await;
        let mut downloaded = Vec::new();
        let error = session
            .download_to(b"h", 0, Some(4), 2, 2, &mut downloaded, |_| {})
            .await
            .expect_err("empty response with another read in flight");
        assert!(matches!(
            error,
            SftpChannelError::Protocol(SftpError::Malformed("empty read response"))
        ));
        let next = session.client_mut().realpath(b"/first").expect("next request");
        assert!(matches!(
            session.send_request(&next).await,
            Err(SftpChannelError::SessionUnusable)
        ));
        assert!(matches!(session.read_response().await, Err(SftpChannelError::SessionUnusable)));
        assert!(matches!(session.request_limits().await, Err(SftpChannelError::SessionUnusable)));

        let mut fresh = SftpSession::open(&connection, 2).await.expect("fresh SFTP channel");
        let request = fresh.client_mut().realpath(b"/first").expect("fresh request");
        fresh.send_request(&request).await.expect("fresh send");
        assert!(matches!(
            fresh.read_response().await.expect("fresh response"),
            SftpPacket::Name { .. }
        ));
        let independent = connection.open_session().await.expect("independent SSH session");
        independent.close().await.expect("close independent session");
        connection.disconnect().await.expect("disconnect client");
    }

    #[tokio::test]
    async fn fully_correlated_file_rejection_and_local_validation_keep_session_usable() {
        let (connection, mut session) = transfer_session(Vec::new(), None, false, false).await;
        let validation = session.upload(b"", 0, b"data", 2, 1, |_| {}).await;
        assert!(matches!(validation, Err(SftpChannelError::Protocol(SftpError::InvalidValue(_)))));
        let rejection = session.upload(b"reject", 0, b"ab", 2, 1, |_| {}).await;
        assert!(matches!(rejection, Err(SftpChannelError::RemoteStatus { code: 4 })));
        assert_eq!(session.pending_requests(), 0);
        let request = session.client_mut().realpath(b"/first").expect("follow-up request");
        session.send_request(&request).await.expect("same session remains usable");
        assert!(matches!(
            session.read_response().await.expect("follow-up"),
            SftpPacket::Name { .. }
        ));
        connection.disconnect().await.expect("disconnect client");
    }

    #[tokio::test]
    async fn streaming_upload_reads_only_declared_bytes_and_reports_contiguous_progress() {
        let (connection, mut session) = transfer_session_with_outbound_window(
            b"abcdef".to_vec(),
            None,
            false,
            false,
            None,
            WriteAckMode::ReorderFirstTwo,
        )
        .await;
        let mut source = TestReader { bytes: b"ghijextra", position: 0, fail_at: None };
        let mut progress = Vec::new();
        let count = session
            .upload_from(b"h", 6, 4, 2, 2, &mut source, |event| progress.push(event))
            .await
            .expect("streaming upload");
        assert_eq!(count, 4);
        assert_eq!(source.position, 4);
        assert_eq!(progress.iter().map(|event| event.offset).collect::<Vec<_>>(), [6, 8, 10]);
        assert!(progress.iter().all(|event| event.total == Some(10)));
        assert_eq!(session.pending_requests(), 0);

        let mut downloaded = Vec::new();
        session
            .download_to(b"h", 0, Some(10), 4, 2, &mut downloaded, |_| {})
            .await
            .expect("read uploaded bytes");
        assert_eq!(downloaded, b"abcdefghij");
        connection.disconnect().await.expect("disconnect client");
    }

    #[tokio::test]
    async fn streaming_upload_validates_before_read_and_handles_zero_length() {
        let (connection, mut session) = transfer_session(Vec::new(), None, false, false).await;
        let mut source = TestReader { bytes: b"bytes", position: 0, fail_at: Some(0) };
        for (handle, offset, length, chunk, pipeline) in [
            (b"h".as_slice(), u64::MAX, 2, 2, 1),
            (b"".as_slice(), 0, 1, 2, 1),
            (b"h".as_slice(), 0, 1, 0, 1),
            (b"h".as_slice(), 0, 1, 2, 0),
        ] {
            assert!(matches!(
                session
                    .upload_from(handle, offset, length, chunk, pipeline, &mut source, |_| {})
                    .await,
                Err(SftpChannelError::Protocol(SftpError::InvalidValue(_)))
            ));
            assert_eq!(source.position, 0);
            assert_eq!(session.pending_requests(), 0);
        }
        let mut progress = Vec::new();
        assert_eq!(
            session
                .upload_from(b"h", 4, 0, 2, 1, &mut source, |event| progress.push(event))
                .await
                .expect("empty upload"),
            0
        );
        assert_eq!(source.position, 0);
        assert_eq!(progress, [SftpTransferProgress { offset: 4, transferred: 0, total: Some(4) }]);
        let request = session.client_mut().realpath(b"/first").expect("follow-up request");
        session.send_request(&request).await.expect("same session remains usable");
        assert!(matches!(session.read_response().await, Ok(SftpPacket::Name { .. })));
        connection.disconnect().await.expect("disconnect client");
    }

    #[tokio::test]
    async fn streaming_upload_preflights_write_frame_and_peer_packet_bounds() {
        let handle = vec![b'h'; crate::MAX_SFTP_HANDLE];
        let bytes = vec![b'x'; MAX_SFTP_PACKET - 64];
        let requested_chunk = u32::try_from(MAX_SFTP_PACKET).expect("SFTP packet fits u32");
        let (connection, mut session) = transfer_session(Vec::new(), None, false, false).await;
        let mut source = TestReader { bytes: &bytes, position: 0, fail_at: None };
        assert_eq!(
            session
                .upload_from(
                    &handle,
                    0,
                    bytes.len() as u64,
                    requested_chunk,
                    2,
                    &mut source,
                    |_| {},
                )
                .await
                .expect("maximum-handle upload"),
            bytes.len() as u64
        );
        assert_eq!(source.position, bytes.len());
        connection.disconnect().await.expect("disconnect client");

        let (connection, mut session) = transfer_session(Vec::new(), None, false, false).await;
        session.limits = Some(SftpLimits {
            max_packet_length: 300,
            max_read_length: 1024,
            max_write_length: 1024,
            max_open_handles: 8,
        });
        let mut source = TestReader { bytes: &bytes, position: 0, fail_at: None };
        assert_eq!(
            session
                .upload_from(&handle, 0, 38, requested_chunk, 2, &mut source, |_| {})
                .await
                .expect("peer-packet-limited upload"),
            38
        );
        assert_eq!(source.position, 38);

        session.limits = Some(SftpLimits { max_packet_length: 280, ..session.limits.unwrap() });
        source.position = 0;
        assert!(matches!(
            session.upload_from(&handle, 0, 1, requested_chunk, 2, &mut source, |_| {}).await,
            Err(SftpChannelError::Protocol(SftpError::InvalidValue("transfer chunk size")))
        ));
        assert_eq!(source.position, 0);
        let request = session.client_mut().realpath(b"/first").expect("follow-up request");
        session.send_request(&request).await.expect("same session remains usable");
        assert!(matches!(session.read_response().await, Ok(SftpPacket::Name { .. })));
        connection.disconnect().await.expect("disconnect client");
    }

    #[tokio::test]
    async fn streaming_upload_source_eof_and_error_invalidate_only_sftp_session() {
        for (bytes, fail_at, expected) in [
            (b"a".as_slice(), None, io::ErrorKind::UnexpectedEof),
            (b"ab".as_slice(), Some(2), io::ErrorKind::PermissionDenied),
        ] {
            let (connection, mut session) = transfer_session(Vec::new(), None, false, false).await;
            let mut source = TestReader { bytes, position: 0, fail_at };
            let error = session
                .upload_from(b"h", 0, 4, 2, 1, &mut source, |_| {})
                .await
                .expect_err("source failure");
            assert!(matches!(error, SftpChannelError::Io(error) if error.kind() == expected));
            assert_eq!(session.pending_requests(), 0);
            assert!(matches!(
                session.read_response().await,
                Err(SftpChannelError::SessionUnusable)
            ));
            let mut fresh = SftpSession::open(&connection, 2).await.expect("fresh SFTP channel");
            let request = fresh.client_mut().realpath(b"/first").expect("fresh request");
            fresh.send_request(&request).await.expect("fresh send");
            assert!(matches!(fresh.read_response().await, Ok(SftpPacket::Name { .. })));
            connection.disconnect().await.expect("disconnect client");
        }
    }

    #[tokio::test]
    async fn streaming_upload_bounds_read_ahead_when_first_ack_is_withheld() {
        let (connection, mut session) = transfer_session_with_outbound_window(
            Vec::new(),
            None,
            false,
            false,
            None,
            WriteAckMode::HoldFirst,
        )
        .await;
        let bytes = [b'x'; 64];
        let mut source = TestReader { bytes: &bytes, position: 0, fail_at: None };
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(100),
                session.upload_from(b"h", 0, 64, 2, 2, &mut source, |_| {}),
            )
            .await
            .is_err()
        );
        assert_eq!(source.position, 4, "completed replies must retain pipeline slots");
        assert_eq!(session.pending_requests(), 0);
        assert!(matches!(session.read_response().await, Err(SftpChannelError::SessionUnusable)));
        let mut fresh = SftpSession::open(&connection, 2).await.expect("fresh SFTP channel");
        let request = fresh.client_mut().realpath(b"/first").expect("fresh request");
        fresh.send_request(&request).await.expect("fresh send");
        assert!(matches!(fresh.read_response().await, Ok(SftpPacket::Name { .. })));
        connection.disconnect().await.expect("disconnect client");
    }

    #[tokio::test]
    async fn pipelined_file_rejection_invalidates_only_its_sftp_channel() {
        let (connection, mut session) = transfer_session(Vec::new(), None, false, false).await;
        let rejection = session.upload(b"reject", 0, b"abcd", 2, 2, |_| {}).await;
        assert!(matches!(rejection, Err(SftpChannelError::RemoteStatus { code: 4 })));
        assert_eq!(session.pending_requests(), 0);
        let request = session.client_mut().realpath(b"/first").expect("follow-up request");
        assert!(matches!(
            session.send_request(&request).await,
            Err(SftpChannelError::SessionUnusable)
        ));
        let mut fresh = SftpSession::open(&connection, 2).await.expect("fresh SFTP channel");
        let request = fresh.client_mut().realpath(b"/first").expect("fresh request");
        fresh.send_request(&request).await.expect("fresh send");
        assert!(matches!(
            fresh.read_response().await.expect("fresh response"),
            SftpPacket::Name { .. }
        ));
        connection.disconnect().await.expect("disconnect client");
    }

    #[tokio::test]
    async fn canceled_or_timed_out_exchanges_invalidate_only_the_sftp_session() {
        let (connection, mut session) = transfer_session(b"data".to_vec(), None, true, false).await;
        let mut downloaded = Vec::new();
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(100),
                session.download_to(b"h", 0, Some(2), 2, 1, &mut downloaded, |_| {})
            )
            .await
            .is_err()
        );
        assert!(matches!(
            session.upload(b"h", 0, b"x", 1, 1, |_| {}).await,
            Err(SftpChannelError::SessionUnusable)
        ));
        let mut fresh = SftpSession::open(&connection, 2).await.expect("fresh SFTP channel");
        let request = fresh.client_mut().realpath(b"/first").expect("fresh request");
        fresh.send_request(&request).await.expect("fresh send");
        assert!(matches!(
            fresh.read_response().await.expect("fresh response"),
            SftpPacket::Name { .. }
        ));
        connection.disconnect().await.expect("disconnect client");

        let (connection, mut session) = transfer_session(Vec::new(), None, false, false).await;
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(100),
                session.upload(b"stall", 0, b"x", 1, 1, |_| {})
            )
            .await
            .is_err()
        );
        assert!(matches!(session.read_response().await, Err(SftpChannelError::SessionUnusable)));
        let mut fresh = SftpSession::open(&connection, 2).await.expect("fresh SFTP channel");
        let request = fresh.client_mut().realpath(b"/second").expect("fresh request");
        fresh.send_request(&request).await.expect("fresh send");
        assert!(matches!(
            fresh.read_response().await.expect("fresh response"),
            SftpPacket::Name { .. }
        ));
        connection.disconnect().await.expect("disconnect client");
    }

    #[tokio::test]
    async fn canceled_low_level_response_wait_invalidates_its_channel() {
        let (connection, mut session) = transfer_session(b"data".to_vec(), None, true, false).await;
        let request = session.client_mut().read(b"h", 0, 2).expect("read request");
        session.send_request(&request).await.expect("send read");
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), session.read_response())
                .await
                .is_err()
        );
        assert!(matches!(session.read_response().await, Err(SftpChannelError::SessionUnusable)));
        let mut fresh = SftpSession::open(&connection, 2).await.expect("fresh SFTP channel");
        let request = fresh.client_mut().realpath(b"/first").expect("fresh request");
        fresh.send_request(&request).await.expect("fresh send");
        assert!(matches!(
            fresh.read_response().await.expect("fresh response"),
            SftpPacket::Name { .. }
        ));
        connection.disconnect().await.expect("disconnect client");
    }

    #[tokio::test]
    async fn channel_transport_failure_invalidates_sftp_but_keeps_parent_connection() {
        let (connection, mut session) = transfer_session(Vec::new(), None, false, false).await;
        let error =
            session.upload(b"close", 0, b"data", 2, 1, |_| {}).await.expect_err("closed channel");
        assert!(matches!(
            error,
            SftpChannelError::Closed | SftpChannelError::Truncated | SftpChannelError::Io(_)
        ));
        assert!(matches!(session.request_limits().await, Err(SftpChannelError::SessionUnusable)));
        let mut fresh = SftpSession::open(&connection, 2).await.expect("fresh SFTP channel");
        let request = fresh.client_mut().realpath(b"/first").expect("fresh request");
        fresh.send_request(&request).await.expect("fresh send");
        assert!(matches!(
            fresh.read_response().await.expect("fresh response"),
            SftpPacket::Name { .. }
        ));
        connection.disconnect().await.expect("disconnect client");
    }

    #[tokio::test]
    async fn exhausted_peer_write_window_invalidates_only_the_sftp_session() {
        let (window_signal, window_observed) = oneshot::channel();
        let (connection, mut session) = transfer_session_with_outbound_window(
            Vec::new(),
            None,
            false,
            false,
            Some(window_signal),
            WriteAckMode::Normal,
        )
        .await;
        let request = session.client_mut().realpath(vec![b'x'; 1024]).expect("large request");
        {
            let send = session.send_request(&request);
            tokio::pin!(send);
            tokio::select! {
                result = &mut send => panic!("outbound write completed: {result:?}"),
                observed = window_observed => observed.expect("peer consumed the write window"),
            }
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(100), &mut send)
                    .await
                    .is_err(),
                "outbound write remained blocked by the peer's exhausted window"
            );
        }
        assert_eq!(session.pending_requests(), 0);
        assert!(matches!(
            session.send_request(&request).await,
            Err(SftpChannelError::SessionUnusable)
        ));
        assert!(matches!(session.read_response().await, Err(SftpChannelError::SessionUnusable)));
        assert!(matches!(session.request_limits().await, Err(SftpChannelError::SessionUnusable)));

        let independent = connection.open_session().await.expect("independent SSH session");
        independent.close().await.expect("close independent session");
        let mut fresh = SftpSession::open(&connection, 2).await.expect("fresh SFTP channel");
        let request = fresh.client_mut().realpath(b"/first").expect("fresh request");
        fresh.send_request(&request).await.expect("fresh send");
        assert!(matches!(
            fresh.read_response().await.expect("fresh response"),
            SftpPacket::Name { .. }
        ));
        assert_eq!(fresh.pending_requests(), 0);
        connection.disconnect().await.expect("disconnect client");
    }

    #[tokio::test]
    async fn malformed_or_truncated_packets_invalidate_only_the_sftp_channel() {
        for (handle, expected_truncated) in
            [(b"malformed-wire".as_slice(), false), (b"truncated-wire".as_slice(), true)]
        {
            let (connection, mut session) = transfer_session(Vec::new(), None, false, false).await;
            let mut downloaded = Vec::new();
            let error = session
                .download_to(handle, 0, Some(2), 2, 1, &mut downloaded, |_| {})
                .await
                .expect_err("bad wire");
            if expected_truncated {
                assert!(matches!(error, SftpChannelError::Truncated));
            } else {
                assert!(matches!(error, SftpChannelError::Protocol(_)));
            }
            assert!(matches!(
                session.read_response().await,
                Err(SftpChannelError::SessionUnusable)
            ));
            let mut fresh = SftpSession::open(&connection, 2).await.expect("fresh SFTP channel");
            let request = fresh.client_mut().realpath(b"/first").expect("fresh request");
            fresh.send_request(&request).await.expect("fresh send");
            assert!(matches!(
                fresh.read_response().await.expect("fresh response"),
                SftpPacket::Name { .. }
            ));
            connection.disconnect().await.expect("disconnect client");
        }
    }

    #[tokio::test]
    async fn sink_failure_with_inflight_responses_invalidates_sftp_channel() {
        let (connection, mut session) =
            transfer_session(b"abcd".to_vec(), None, false, false).await;
        let (mut sink, reader) = tokio::io::duplex(1);
        drop(reader);
        let error = session
            .download_to(b"h", 0, Some(4), 2, 2, &mut sink, |_| {})
            .await
            .expect_err("closed sink");
        assert!(matches!(error, SftpChannelError::Io(_)));
        assert!(matches!(session.request_limits().await, Err(SftpChannelError::SessionUnusable)));
        let mut fresh = SftpSession::open(&connection, 2).await.expect("fresh SFTP channel");
        let request = fresh.client_mut().realpath(b"/first").expect("fresh request");
        fresh.send_request(&request).await.expect("fresh send");
        assert!(matches!(
            fresh.read_response().await.expect("fresh response"),
            SftpPacket::Name { .. }
        ));
        connection.disconnect().await.expect("disconnect client");
    }

    async fn assert_fstatvfs(session: &mut SftpSession, handle: &[u8], open: bool) {
        let request = session.client_mut().fstatvfs(handle.to_vec()).expect("fstatvfs request");
        session.send_request(&request).await.expect("send fstatvfs");
        let response = session.read_response().await.expect("read fstatvfs");
        if open {
            let stats = response.statvfs_response().expect("decode fstatvfs");
            assert_eq!(stats.block_size, 4096);
            assert_eq!(stats.name_max, 255);
        } else {
            assert!(matches!(response, SftpPacket::Status { code: 4, .. }));
        }
        assert_eq!(session.pending_requests(), 0);
    }

    async fn assert_fstat(session: &mut SftpSession, handle: &[u8], expected_size: Option<u64>) {
        let request = session.client_mut().fstat(handle.to_vec()).expect("fstat request");
        session.send_request(&request).await.expect("send fstat");
        let response = session.read_response().await.expect("read fstat");
        if let Some(size) = expected_size {
            assert!(matches!(
                response,
                SftpPacket::Attrs { attrs: SftpAttributes { size: Some(actual), .. }, .. } if actual == size
            ));
        } else {
            assert!(matches!(response, SftpPacket::Status { code: 4, .. }));
        }
        assert_eq!(session.pending_requests(), 0);
    }

    async fn assert_fsetstat(session: &mut SftpSession, handle: &[u8], size: u64, open: bool) {
        let request = session
            .client_mut()
            .fsetstat(
                handle.to_vec(),
                SftpAttributes { size: Some(size), ..SftpAttributes::default() },
            )
            .expect("fsetstat request");
        session.send_request(&request).await.expect("send fsetstat");
        let response = session.read_response().await.expect("read fsetstat");
        assert!(matches!(response, SftpPacket::Status { code, .. } if (code == 0) == open));
        assert_eq!(session.pending_requests(), 0);
    }

    async fn assert_fsetstat_open_round_trip(session: &mut SftpSession, handle: &[u8]) {
        assert_fsetstat(session, handle, 13, true).await;
        assert_fstat(session, handle, Some(13)).await;
        assert_fsetstat(session, handle, 12, true).await;
        assert_fstat(session, handle, Some(12)).await;
    }

    async fn assert_fsetstat_closed(session: &mut SftpSession, handle: &[u8]) {
        assert_fsetstat(session, handle, 13, false).await;
        let reopen = session.client_mut().open(b"file", 1, SftpAttributes::default()).unwrap();
        session.send_request(&reopen).await.expect("send reopen");
        let reopened = match session.read_response().await.expect("read reopen") {
            SftpPacket::Handle { handle, .. } => handle,
            other => panic!("unexpected reopen response: {other:?}"),
        };
        assert_fstat(session, &reopened, Some(12)).await;
        let close = session.client_mut().close(reopened).unwrap();
        session.send_request(&close).await.expect("send reclose");
        assert!(matches!(
            session.read_response().await.expect("read reclose"),
            SftpPacket::Status { code: 0, .. }
        ));
        assert_eq!(session.pending_requests(), 0);
    }

    async fn assert_setstat(session: &mut SftpSession) {
        let changed = SftpAttributes {
            size: Some(13),
            access_time: Some(1_650_000_000),
            modify_time: Some(1_650_000_000),
            ..SftpAttributes::default()
        };
        let missing = session.client_mut().setstat(b"missing", changed.clone()).unwrap();
        session.send_request(&missing).await.expect("send missing setstat");
        assert!(matches!(
            session.read_response().await.expect("read missing setstat"),
            SftpPacket::Status { code: 2, .. }
        ));
        assert_eq!(session.pending_requests(), 0);

        let set = session.client_mut().setstat(b"file", changed).unwrap();
        session.send_request(&set).await.expect("send setstat");
        assert!(matches!(
            session.read_response().await.expect("read setstat"),
            SftpPacket::Status { code: 0, .. }
        ));
        assert_eq!(session.pending_requests(), 0);
        let stat = session.client_mut().stat(b"file").unwrap();
        session.send_request(&stat).await.expect("send stat after setstat");
        assert!(matches!(
            session.read_response().await.expect("read stat after setstat"),
            SftpPacket::Attrs { attrs, .. }
                if attrs.size == Some(13) && attrs.modify_time == Some(1_650_000_000)
        ));
        assert_eq!(session.pending_requests(), 0);

        let restore = session
            .client_mut()
            .setstat(
                b"file",
                SftpAttributes {
                    size: Some(12),
                    access_time: Some(1_700_000_000),
                    modify_time: Some(1_700_000_000),
                    ..SftpAttributes::default()
                },
            )
            .unwrap();
        session.send_request(&restore).await.expect("send truncating setstat");
        assert!(matches!(
            session.read_response().await.expect("read truncating setstat"),
            SftpPacket::Status { code: 0, .. }
        ));
        assert_eq!(session.pending_requests(), 0);
        let stat = session.client_mut().stat(b"file").unwrap();
        session.send_request(&stat).await.expect("send stat after truncation");
        assert!(matches!(
            session.read_response().await.expect("read stat after truncation"),
            SftpPacket::Attrs { attrs, .. }
                if attrs.size == Some(12) && attrs.modify_time == Some(1_700_000_000)
        ));
        assert_eq!(session.pending_requests(), 0);
        assert_file_bytes(session, b"file", b"linked bytes").await;
    }

    async fn assert_hardlink(session: &mut SftpSession) {
        let missing = session
            .client_mut()
            .hardlink(b"missing", b"missing-link")
            .expect("missing-source hardlink request");
        session.send_request(&missing).await.expect("send missing-source hardlink");
        assert!(matches!(
            session.read_response().await.expect("read missing-source hardlink"),
            SftpPacket::Status { code: 2, .. }
        ));
        assert_eq!(session.pending_requests(), 0);

        let link = session.client_mut().hardlink(b"file", b"link").expect("hardlink request");
        session.send_request(&link).await.expect("send hardlink");
        assert!(matches!(
            session.read_response().await.expect("read hardlink"),
            SftpPacket::Status { code: 0, .. }
        ));
        assert_eq!(session.pending_requests(), 0);
        let existing = session.client_mut().hardlink(b"file", b"link").expect("existing hardlink");
        session.send_request(&existing).await.expect("send existing hardlink");
        assert!(matches!(
            session.read_response().await.expect("read existing hardlink"),
            SftpPacket::Status { code: 4, .. }
        ));
        assert_eq!(session.pending_requests(), 0);

        let open = session
            .client_mut()
            .open(b"link", 1, SftpAttributes::default())
            .expect("open linked file");
        session.send_request(&open).await.expect("send linked-file open");
        let handle = match session.read_response().await.expect("read linked-file open") {
            SftpPacket::Handle { handle, .. } => handle,
            other => panic!("unexpected linked-file open response: {other:?}"),
        };
        let read = session.client_mut().read(handle.clone(), 0, 12).expect("read linked file");
        session.send_request(&read).await.expect("send linked-file read");
        assert!(matches!(
            session.read_response().await.expect("read linked-file data"),
            SftpPacket::Data { data, .. } if data == b"linked bytes"
        ));
        assert_eq!(session.pending_requests(), 0);
        let close = session.client_mut().close(handle).expect("close linked file");
        session.send_request(&close).await.expect("send linked-file close");
        assert!(matches!(
            session.read_response().await.expect("read linked-file close"),
            SftpPacket::Status { code: 0, .. }
        ));
        let remove = session.client_mut().remove(b"link").expect("remove linked file");
        session.send_request(&remove).await.expect("send linked-file remove");
        assert!(matches!(
            session.read_response().await.expect("read linked-file remove"),
            SftpPacket::Status { code: 0, .. }
        ));
        assert_eq!(session.pending_requests(), 0);
        let absent = session
            .client_mut()
            .open(b"link", 1, SftpAttributes::default())
            .expect("open removed link");
        session.send_request(&absent).await.expect("send removed-link open");
        assert!(matches!(
            session.read_response().await.expect("read removed-link open"),
            SftpPacket::Status { code: 2, .. }
        ));
        assert_eq!(session.pending_requests(), 0);
    }

    async fn assert_rename_status(session: &mut SftpSession, old: &[u8], new: &[u8], code: u32) {
        let request = session.client_mut().posix_rename(old, new).expect("posix-rename request");
        session.send_request(&request).await.expect("send posix-rename");
        assert!(matches!(
            session.read_response().await.expect("read posix-rename"),
            SftpPacket::Status { code: actual, .. } if actual == code
        ));
        assert_eq!(session.pending_requests(), 0);
    }

    async fn assert_standard_rename_status(
        session: &mut SftpSession,
        old: &[u8],
        new: &[u8],
        code: u32,
    ) {
        let request = session.client_mut().rename(old, new).expect("standard rename request");
        session.send_request(&request).await.expect("send standard rename");
        assert!(matches!(
            session.read_response().await.expect("read standard rename"),
            SftpPacket::Status { code: actual, .. } if actual == code
        ));
        assert_eq!(session.pending_requests(), 0);
    }

    async fn assert_file_bytes(session: &mut SftpSession, path: &[u8], expected: &[u8]) {
        let open =
            session.client_mut().open(path, 1, SftpAttributes::default()).expect("open file");
        session.send_request(&open).await.expect("send file open");
        let handle = match session.read_response().await.expect("read file open") {
            SftpPacket::Handle { handle, .. } => handle,
            other => panic!("unexpected file open response: {other:?}"),
        };
        let length = u32::try_from(expected.len()).expect("bounded expected file length");
        let read = session.client_mut().read(handle.clone(), 0, length).expect("read file");
        session.send_request(&read).await.expect("send file read");
        assert!(matches!(
            session.read_response().await.expect("read file bytes"),
            SftpPacket::Data { data, .. } if data == expected
        ));
        assert_eq!(session.pending_requests(), 0);
        let close = session.client_mut().close(handle).expect("close file");
        session.send_request(&close).await.expect("send file close");
        assert!(matches!(
            session.read_response().await.expect("read file close"),
            SftpPacket::Status { code: 0, .. }
        ));
        assert_eq!(session.pending_requests(), 0);
    }

    async fn assert_missing_file(session: &mut SftpSession, path: &[u8]) {
        let open = session
            .client_mut()
            .open(path, 1, SftpAttributes::default())
            .expect("open missing file");
        session.send_request(&open).await.expect("send missing-file open");
        assert!(matches!(
            session.read_response().await.expect("read missing-file open"),
            SftpPacket::Status { code: 2, .. }
        ));
        assert_eq!(session.pending_requests(), 0);
    }

    async fn assert_expand_path(session: &mut SftpSession) {
        assert!(
            session
                .extensions()
                .iter()
                .any(|extension| extension.name == b"expand-path@openssh.com")
        );
        let request = session.client_mut().expand_path(b"file").expect("expand file path");
        session.send_request(&request).await.expect("send expand-path");
        assert!(matches!(
            session.read_response().await.expect("read expand-path"),
            SftpPacket::Name { entries, .. }
                if entries.len() == 1 && entries[0].filename == b"/srv/file"
        ));
        assert_eq!(session.pending_requests(), 0);
        assert_file_bytes(session, b"/srv/file", b"linked bytes").await;

        let missing = session.client_mut().expand_path(b"missing").expect("expand missing path");
        session.send_request(&missing).await.expect("send missing expand-path");
        assert!(matches!(
            session.read_response().await.expect("read missing expand-path"),
            SftpPacket::Name { entries, .. }
                if entries.len() == 1 && entries[0].filename == b"/srv/missing"
        ));
        assert_eq!(session.pending_requests(), 0);
        assert_missing_file(session, b"/srv/missing").await;
    }

    async fn assert_posix_rename(session: &mut SftpSession) {
        assert!(
            session
                .extensions()
                .iter()
                .any(|extension| extension.name == b"posix-rename@openssh.com")
        );
        assert_rename_status(session, b"missing", b"missing-renamed", 2).await;
        assert_file_bytes(session, b"replacement", b"previous destination contents").await;
        assert_rename_status(session, b"file", b"renamed", 0).await;
        assert_missing_file(session, b"file").await;
        assert_file_bytes(session, b"renamed", b"linked bytes").await;
        assert_rename_status(session, b"renamed", b"replacement", 0).await;
        assert_missing_file(session, b"renamed").await;
        assert_file_bytes(session, b"replacement", b"linked bytes").await;
        let remove = session.client_mut().remove(b"replacement").expect("remove replacement");
        session.send_request(&remove).await.expect("send replacement remove");
        assert!(matches!(
            session.read_response().await.expect("read replacement remove"),
            SftpPacket::Status { code: 0, .. }
        ));
        assert_eq!(session.pending_requests(), 0);
        assert_missing_file(session, b"replacement").await;
    }

    async fn assert_standard_rename(session: &mut SftpSession) {
        assert_standard_rename_status(session, b"missing", b"missing-renamed", 2).await;
        assert_missing_file(session, b"missing-renamed").await;
        assert_standard_rename_status(session, b"file", b"replacement", 4).await;
        assert_file_bytes(session, b"file", b"linked bytes").await;
        assert_file_bytes(session, b"replacement", b"previous destination contents").await;
        assert_standard_rename_status(session, b"file", b"renamed", 0).await;
        assert_missing_file(session, b"file").await;
        assert_file_bytes(session, b"renamed", b"linked bytes").await;
        assert_standard_rename_status(session, b"renamed", b"file", 0).await;
        assert_missing_file(session, b"renamed").await;
        assert_file_bytes(session, b"file", b"linked bytes").await;
    }

    async fn assert_missing_statvfs(session: &mut SftpSession) {
        let missing = session.client_mut().statvfs(b"missing").expect("missing statvfs request");
        session.send_request(&missing).await.expect("send missing statvfs");
        assert!(matches!(
            session.read_response().await.expect("read missing statvfs"),
            SftpPacket::Status { code: 2, .. }
        ));
        assert_eq!(session.pending_requests(), 0);
    }

    async fn assert_lsetstat(session: &mut SftpSession) {
        assert!(
            session.extensions().iter().any(|extension| extension.name == b"lsetstat@openssh.com")
        );
        let attrs = SftpAttributes {
            access_time: Some(1_600_000_000),
            modify_time: Some(1_600_000_000),
            ..SftpAttributes::default()
        };
        let missing = session.client_mut().lsetstat(b"missing", &attrs).unwrap();
        session.send_request(&missing).await.unwrap();
        assert!(matches!(
            session.read_response().await.unwrap(),
            SftpPacket::Status { code: 2, .. }
        ));
        assert_eq!(session.pending_requests(), 0);

        let missing_link = session.client_mut().readlink(b"missing").unwrap();
        session.send_request(&missing_link).await.unwrap();
        assert!(matches!(
            session.read_response().await.unwrap(),
            SftpPacket::Status { code: 2, .. }
        ));
        assert_eq!(session.pending_requests(), 0);
        let create_link = session.client_mut().symlink(b"symlink", b"file").unwrap();
        session.send_request(&create_link).await.unwrap();
        assert!(matches!(
            session.read_response().await.unwrap(),
            SftpPacket::Status { code: 0, .. }
        ));
        assert_eq!(session.pending_requests(), 0);
        let read_link = session.client_mut().readlink(b"symlink").unwrap();
        session.send_request(&read_link).await.unwrap();
        assert!(matches!(
            session.read_response().await.unwrap(),
            SftpPacket::Name { entries, .. }
                if entries.len() == 1 && entries[0].filename == b"file"
        ));
        assert_eq!(session.pending_requests(), 0);

        let request = session.client_mut().lsetstat(b"symlink", &attrs).unwrap();
        session.send_request(&request).await.unwrap();
        assert!(matches!(
            session.read_response().await.unwrap(),
            SftpPacket::Status { code: 0, .. }
        ));
        assert_eq!(session.pending_requests(), 0);
        let link = session.client_mut().lstat(b"symlink").unwrap();
        session.send_request(&link).await.unwrap();
        assert!(matches!(
            session.read_response().await.unwrap(),
            SftpPacket::Attrs { attrs, .. } if attrs.modify_time == Some(1_600_000_000)
        ));
        assert_eq!(session.pending_requests(), 0);
        let target = session.client_mut().stat(b"symlink").unwrap();
        session.send_request(&target).await.unwrap();
        assert!(matches!(
            session.read_response().await.unwrap(),
            SftpPacket::Attrs { attrs, .. } if attrs.modify_time == Some(1_700_000_000)
        ));
        assert_eq!(session.pending_requests(), 0);
        let remove_link = session.client_mut().remove(b"symlink").unwrap();
        session.send_request(&remove_link).await.unwrap();
        assert!(matches!(
            session.read_response().await.unwrap(),
            SftpPacket::Status { code: 0, .. }
        ));
        assert_eq!(session.pending_requests(), 0);
        let after_cleanup = session.client_mut().readlink(b"symlink").unwrap();
        session.send_request(&after_cleanup).await.unwrap();
        assert!(matches!(
            session.read_response().await.unwrap(),
            SftpPacket::Status { code: 2, .. }
        ));
        assert_eq!(session.pending_requests(), 0);
    }

    async fn assert_initial_requests(session: &mut SftpSession) {
        assert_eq!(session.extensions().len(), 8);
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
            SftpPacket::Name { id: 2, entries }
                if entries.len() == 1 && entries[0].filename == b"/srv"
        ));
        assert_eq!(session.pending_requests(), 0);
        let file = session.client_mut().realpath(b"./file").expect("file realpath request");
        session.send_request(&file).await.expect("write file realpath");
        assert!(matches!(
            session.read_response().await.expect("read file realpath"),
            SftpPacket::Name { entries, .. }
                if entries.len() == 1 && entries[0].filename == b"/srv/file"
        ));
        assert_eq!(session.pending_requests(), 0);
        let missing = session.client_mut().realpath(b"missing").expect("missing realpath request");
        session.send_request(&missing).await.expect("write missing realpath");
        assert!(matches!(
            session.read_response().await.expect("read missing realpath"),
            SftpPacket::Name { entries, .. }
                if entries.len() == 1 && entries[0].filename == b"/srv/missing"
        ));
        assert_eq!(session.pending_requests(), 0);
        let invalid =
            session.client_mut().realpath(b"file/child").expect("invalid realpath request");
        session.send_request(&invalid).await.expect("write invalid realpath");
        assert!(matches!(
            session.read_response().await.expect("read invalid realpath"),
            SftpPacket::Status { code: 2, .. }
        ));
        assert_eq!(session.pending_requests(), 0);
        let statvfs = session.client_mut().statvfs(b".").expect("statvfs request");
        session.send_request(&statvfs).await.expect("send statvfs");
        let stats =
            session.read_response().await.expect("read statvfs").statvfs_response().unwrap();
        assert_eq!(stats.block_size, 4096);
        assert_eq!(stats.name_max, 255);
        assert_eq!(session.pending_requests(), 0);
    }

    #[tokio::test]
    async fn copy_data_round_trips_over_authenticated_channel() {
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
                    file: b"linked bytes".to_vec(),
                    file_mtime: None,
                    advertise_limits: false,
                    advertise_statvfs: false,
                    extension_handle_open: Some(false),
                    hardlink_created: None,
                    rename_phase: None,
                    expand_path_prefix: None,
                    copy_data_target: Some(b"0123456789".to_vec()),
                    lsetstat_link_mtime: None,
                    symlink_target: None,
                    directory: None,
                    read_reply_limit: None,
                    reorder_first_reads: false,
                    deferred_read_response: None,
                    write_ack_mode: WriteAckMode::Normal,
                    deferred_write_response: None,
                    outbound_window_signal: None,
                },
            )
            .await;
        });

        let verifier = |_host: &str, _key: &HostKey| Ok(());
        let config = ClientConfig::new("127.0.0.1", address.port(), verifier).expect("config");
        let mut connection = ClientConnection::connect(config).await.expect("connect client");
        connection.authenticate_password("user", b"password").await.expect("authenticate client");
        let mut session = SftpSession::open(&connection, 2).await.expect("open sftp session");
        assert!(session.extensions().iter().any(|extension| extension.name == b"copy-data"));

        for (path, flags, expected) in
            [(b"file".as_slice(), 1, b"h".as_slice()), (b"copy-target", 3, b"copy")]
        {
            let open = session.client_mut().open(path, flags, SftpAttributes::default()).unwrap();
            session.send_request(&open).await.unwrap();
            assert!(matches!(
                session.read_response().await.unwrap(),
                SftpPacket::Handle { handle, .. } if handle == expected
            ));
            assert_eq!(session.pending_requests(), 0);
        }

        let copy = session.client_mut().copy_data(b"h", 2, 4, b"copy", 1).unwrap();
        session.send_request(&copy).await.unwrap();
        assert!(matches!(
            session.read_response().await.unwrap(),
            SftpPacket::Status { code: 0, .. }
        ));
        assert_eq!(session.pending_requests(), 0);
        let read = session.client_mut().read(b"copy", 0, 10).unwrap();
        session.send_request(&read).await.unwrap();
        assert!(matches!(
            session.read_response().await.unwrap(),
            SftpPacket::Data { data, .. } if data == b"0nked56789"
        ));
        assert_eq!(session.pending_requests(), 0);

        let invalid = session.client_mut().copy_data(b"invalid", 2, 4, b"copy", 1).unwrap();
        session.send_request(&invalid).await.unwrap();
        assert!(matches!(
            session.read_response().await.unwrap(),
            SftpPacket::Status { code: 4, .. }
        ));
        assert_eq!(session.pending_requests(), 0);
        let close = session.client_mut().close(b"h").unwrap();
        session.send_request(&close).await.unwrap();
        assert!(matches!(
            session.read_response().await.unwrap(),
            SftpPacket::Status { code: 0, .. }
        ));
        let closed = session.client_mut().copy_data(b"h", 2, 4, b"copy", 1).unwrap();
        session.send_request(&closed).await.unwrap();
        assert!(matches!(
            session.read_response().await.unwrap(),
            SftpPacket::Status { code: 4, .. }
        ));
        assert_eq!(session.pending_requests(), 0);
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
                    file: b"linked bytes".to_vec(),
                    file_mtime: Some(1_700_000_000),
                    advertise_limits: true,
                    advertise_statvfs: true,
                    extension_handle_open: Some(false),
                    hardlink_created: Some(false),
                    rename_phase: Some(RenamePhase::Original),
                    expand_path_prefix: Some(b"/srv/"),
                    copy_data_target: None,
                    lsetstat_link_mtime: Some(1_700_000_001),
                    symlink_target: None,
                    directory: None,
                    read_reply_limit: None,
                    reorder_first_reads: false,
                    deferred_read_response: None,
                    write_ack_mode: WriteAckMode::Normal,
                    deferred_write_response: None,
                    outbound_window_signal: None,
                },
            )
            .await;
        });

        let verifier = |_host: &str, _key: &HostKey| Ok(());
        let config = ClientConfig::new("127.0.0.1", address.port(), verifier).expect("config");
        let mut connection = ClientConnection::connect(config).await.expect("connect client");
        connection.authenticate_password("user", b"password").await.expect("authenticate client");
        let mut session = SftpSession::open(&connection, 2).await.expect("open sftp session");
        assert_initial_requests(&mut session).await;

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
        assert_fstatvfs(&mut session, &handle, true).await;
        assert_fstat(&mut session, &handle, Some(12)).await;
        assert_fsetstat_open_round_trip(&mut session, &handle).await;
        let close = session.client_mut().close(handle.clone()).expect("close request");
        session.send_request(&close).await.expect("send close");
        assert!(matches!(
            session.read_response().await.expect("read close"),
            SftpPacket::Status { code: 0, .. }
        ));
        let closed_fsync =
            session.client_mut().fsync(handle.clone()).expect("closed fsync request");
        session.send_request(&closed_fsync).await.expect("send closed fsync");
        assert!(matches!(
            session.read_response().await.expect("read closed fsync"),
            SftpPacket::Status { code: 4, .. }
        ));
        assert_eq!(session.pending_requests(), 0);
        assert_fstatvfs(&mut session, &handle, false).await;
        assert_fstat(&mut session, &handle, None).await;
        assert_fsetstat_closed(&mut session, &handle).await;
        assert_setstat(&mut session).await;
        assert_hardlink(&mut session).await;
        assert_expand_path(&mut session).await;
        assert_lsetstat(&mut session).await;
        assert_standard_rename(&mut session).await;
        assert_posix_rename(&mut session).await;

        assert_missing_statvfs(&mut session).await;
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
                    file_mtime: None,
                    advertise_limits: false,
                    advertise_statvfs: false,
                    extension_handle_open: None,
                    hardlink_created: None,
                    rename_phase: None,
                    expand_path_prefix: None,
                    copy_data_target: None,
                    lsetstat_link_mtime: None,
                    symlink_target: None,
                    directory: None,
                    read_reply_limit: None,
                    reorder_first_reads: false,
                    deferred_read_response: None,
                    write_ack_mode: WriteAckMode::Normal,
                    deferred_write_response: None,
                    outbound_window_signal: None,
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
                    file_mtime: None,
                    advertise_limits: false,
                    advertise_statvfs: false,
                    extension_handle_open: None,
                    hardlink_created: None,
                    rename_phase: None,
                    expand_path_prefix: None,
                    copy_data_target: None,
                    lsetstat_link_mtime: None,
                    symlink_target: None,
                    directory: None,
                    read_reply_limit: None,
                    reorder_first_reads: false,
                    deferred_read_response: None,
                    write_ack_mode: WriteAckMode::Normal,
                    deferred_write_response: None,
                    outbound_window_signal: None,
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
