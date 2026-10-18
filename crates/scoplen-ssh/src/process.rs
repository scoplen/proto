// SPDX-License-Identifier: Apache-2.0
//! A bounded desktop `ProxyCommand` byte transport.
//!
//! The command is started directly with separated arguments; no shell is involved.  Standard
//! input and output form the byte stream consumed by an SSH engine.  The child is always reaped
//! when the transport is dropped, and the public boundary never exposes command output or paths
//! in an error message.

#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]

use std::{
    ffi::OsStr,
    fmt,
    future::Future,
    io::{self, Read, Write},
    net::{Shutdown, SocketAddr},
    pin::Pin,
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    task::JoinHandle,
};

use crate::tcp::{Transport, TransportError, TransportOperation};

/// Maximum length of a `ProxyCommand` executable path or name.
pub const MAX_PROXY_COMMAND_PROGRAM: usize = 4096;
/// Maximum number of arguments accepted by a `ProxyCommand`.
pub const MAX_PROXY_COMMAND_ARGUMENTS: usize = 64;
/// Maximum length of one `ProxyCommand` argument.
pub const MAX_PROXY_COMMAND_ARGUMENT: usize = 4096;

/// Errors raised before a `ProxyCommand` transport can be created.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProxyCommandError {
    /// The executable path or name was empty.
    #[error("ProxyCommand program is empty")]
    EmptyProgram,
    /// The executable path or name exceeded the bound.
    #[error("ProxyCommand program exceeds the {max}-byte limit")]
    ProgramTooLong { max: usize },
    /// An argument exceeded the bound.
    #[error("ProxyCommand argument exceeds the {max}-byte limit")]
    ArgumentTooLong { max: usize },
    /// The argument list exceeded the bound.
    #[error("ProxyCommand has more than {max} arguments")]
    TooManyArguments { max: usize },
    /// The operating system rejected process creation.
    #[error("ProxyCommand process could not be started: {kind:?}")]
    Spawn { kind: io::ErrorKind },
    /// A piped standard stream was unexpectedly unavailable after process creation.
    #[error("ProxyCommand process did not provide {stream}")]
    MissingPipe { stream: &'static str },
}

/// A byte transport backed by a directly spawned `ProxyCommand` process.
pub struct ProxyCommandTransport {
    stdin: Mutex<Option<ChildStdin>>,
    stdout: Mutex<Option<ChildStdout>>,
    child: Mutex<Child>,
}

impl fmt::Debug for ProxyCommandTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("ProxyCommandTransport").finish_non_exhaustive()
    }
}

impl ProxyCommandTransport {
    /// Spawn a process with piped standard input and output.
    ///
    /// Arguments are passed directly to [`Command`]. No shell, interpolation, environment
    /// expansion, or implicit command-line parsing is performed. Standard error is discarded so
    /// an unbounded child diagnostic cannot deadlock the byte transport.
    pub fn spawn<I, A>(program: impl AsRef<OsStr>, args: I) -> Result<Self, ProxyCommandError>
    where
        I: IntoIterator<Item = A>,
        A: AsRef<OsStr>,
    {
        let program = program.as_ref();
        validate_program(program)?;

        let mut arguments = Vec::new();
        for argument in args {
            if arguments.len() >= MAX_PROXY_COMMAND_ARGUMENTS {
                return Err(ProxyCommandError::TooManyArguments {
                    max: MAX_PROXY_COMMAND_ARGUMENTS,
                });
            }
            let argument = argument.as_ref();
            validate_argument(argument)?;
            arguments.push(argument.to_os_string());
        }

        let mut command = Command::new(program);
        command.args(&arguments).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null());
        let mut child =
            command.spawn().map_err(|error| ProxyCommandError::Spawn { kind: error.kind() })?;
        let Some(stdin) = child.stdin.take() else {
            reap_child(&mut child);
            return Err(ProxyCommandError::MissingPipe { stream: "stdin" });
        };
        let Some(stdout) = child.stdout.take() else {
            reap_child(&mut child);
            return Err(ProxyCommandError::MissingPipe { stream: "stdout" });
        };
        Ok(Self {
            stdin: Mutex::new(Some(stdin)),
            stdout: Mutex::new(Some(stdout)),
            child: Mutex::new(child),
        })
    }

    fn lock_error() -> io::Error {
        io::Error::new(io::ErrorKind::Other, "ProxyCommand transport state is unavailable")
    }

    fn take_stdin(&self) {
        if let Ok(mut stdin) = self.stdin.lock() {
            let _ = stdin.take();
        }
    }

    fn take_stdout(&self) {
        if let Ok(mut stdout) = self.stdout.lock() {
            let _ = stdout.take();
        }
    }

    fn kill_child(&self) -> io::Result<()> {
        let mut child = self.child.lock().map_err(|_| Self::lock_error())?;
        if let Err(error) = child.kill() {
            if error.kind() != io::ErrorKind::InvalidInput {
                return Err(error);
            }
        }
        child.wait().map(|_| ())
    }

    fn read_shared(&self, buffer: &mut [u8]) -> io::Result<usize> {
        let mut stdout = self.stdout.lock().map_err(|_| Self::lock_error())?;
        let stdout = stdout.as_mut().ok_or_else(|| {
            io::Error::new(io::ErrorKind::BrokenPipe, "ProxyCommand stdout is closed")
        })?;
        stdout.read(buffer)
    }

    fn write_shared(&self, buffer: &[u8]) -> io::Result<usize> {
        let mut stdin = self.stdin.lock().map_err(|_| Self::lock_error())?;
        let stdin = stdin.as_mut().ok_or_else(|| {
            io::Error::new(io::ErrorKind::BrokenPipe, "ProxyCommand stdin is closed")
        })?;
        stdin.write(buffer)
    }

    fn flush_shared(&self) -> io::Result<()> {
        let mut stdin = self.stdin.lock().map_err(|_| Self::lock_error())?;
        let stdin = stdin.as_mut().ok_or_else(|| {
            io::Error::new(io::ErrorKind::BrokenPipe, "ProxyCommand stdin is closed")
        })?;
        stdin.flush()
    }
}

/// An asynchronous stream adapter for a bounded [`ProxyCommandTransport`].
///
/// The child process owns blocking standard pipes, so each operation runs on a blocking worker.
/// Read and write use separate internal locks and can make progress concurrently while the SSH
/// engine waits for the peer. Each copied operation buffer is bounded.
pub(crate) struct ProxyCommandStream {
    inner: Arc<ProxyCommandTransport>,
    read_task: Option<JoinHandle<io::Result<Vec<u8>>>>,
    write_task: Option<JoinHandle<io::Result<usize>>>,
    flush_task: Option<JoinHandle<io::Result<()>>>,
    shutdown_task: Option<JoinHandle<io::Result<()>>>,
}

pub(crate) struct ProxyCommandTerminationGuard {
    inner: Option<Arc<ProxyCommandTransport>>,
}

impl ProxyCommandTerminationGuard {
    pub(crate) fn disarm(&mut self) {
        self.inner = None;
    }
}

impl Drop for ProxyCommandTerminationGuard {
    fn drop(&mut self) {
        if let Some(inner) = &self.inner {
            let _ = inner.kill_child();
        }
    }
}

impl fmt::Debug for ProxyCommandStream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("ProxyCommandStream").finish_non_exhaustive()
    }
}

impl ProxyCommandStream {
    const MAX_ASYNC_IO: usize = 64 * 1024;

    pub(crate) fn new(inner: ProxyCommandTransport) -> Self {
        Self {
            inner: Arc::new(inner),
            read_task: None,
            write_task: None,
            flush_task: None,
            shutdown_task: None,
        }
    }

    pub(crate) fn termination_guard(&self) -> ProxyCommandTerminationGuard {
        ProxyCommandTerminationGuard { inner: Some(Arc::clone(&self.inner)) }
    }

    fn join_error(error: &tokio::task::JoinError) -> io::Error {
        io::Error::other(format!("ProxyCommand I/O worker stopped: {error}"))
    }
}

impl AsyncRead for ProxyCommandStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.read_task.is_none() {
            let inner = Arc::clone(&self.inner);
            let capacity = buffer.remaining().min(Self::MAX_ASYNC_IO);
            self.read_task = Some(tokio::task::spawn_blocking(move || {
                let mut data = vec![0; capacity];
                let length = inner.read_shared(&mut data)?;
                data.truncate(length);
                Ok(data)
            }));
        }
        let task = self.read_task.as_mut().expect("read task is present");
        match Pin::new(task).poll(context) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.read_task = None;
                let data = match result {
                    Ok(result) => result?,
                    Err(error) => return Poll::Ready(Err(Self::join_error(&error))),
                };
                buffer.put_slice(&data);
                Poll::Ready(Ok(()))
            }
        }
    }
}

impl AsyncWrite for ProxyCommandStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.write_task.is_none() {
            let inner = Arc::clone(&self.inner);
            let data = buffer[..buffer.len().min(Self::MAX_ASYNC_IO)].to_vec();
            self.write_task = Some(tokio::task::spawn_blocking(move || inner.write_shared(&data)));
        }
        let task = self.write_task.as_mut().expect("write task is present");
        match Pin::new(task).poll(context) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.write_task = None;
                match result {
                    Ok(result) => Poll::Ready(result),
                    Err(error) => Poll::Ready(Err(Self::join_error(&error))),
                }
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.flush_task.is_none() {
            let inner = Arc::clone(&self.inner);
            self.flush_task = Some(tokio::task::spawn_blocking(move || inner.flush_shared()));
        }
        let task = self.flush_task.as_mut().expect("flush task is present");
        match Pin::new(task).poll(context) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.flush_task = None;
                match result {
                    Ok(result) => Poll::Ready(result),
                    Err(error) => Poll::Ready(Err(Self::join_error(&error))),
                }
            }
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.shutdown_task.is_none() {
            let inner = Arc::clone(&self.inner);
            self.shutdown_task = Some(tokio::task::spawn_blocking(move || {
                inner
                    .kill_child()
                    .map_err(|error| io::Error::new(error.kind(), "ProxyCommand shutdown failed"))
            }));
        }
        let task = self.shutdown_task.as_mut().expect("shutdown task is present");
        match Pin::new(task).poll(context) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.shutdown_task = None;
                match result {
                    Ok(result) => Poll::Ready(result),
                    Err(error) => Poll::Ready(Err(Self::join_error(&error))),
                }
            }
        }
    }
}

impl Drop for ProxyCommandStream {
    fn drop(&mut self) {
        // A blocking worker may still own a clone of `inner` after its JoinHandle is dropped.
        // Kill first: a blocking read or write may hold a pipe lock until the child exits.
        let _ = self.inner.kill_child();
        self.inner.take_stdin();
        self.inner.take_stdout();
    }
}

impl Transport for ProxyCommandTransport {
    fn read(&mut self, buffer: &mut [u8]) -> Result<usize, TransportError> {
        self.read_shared(buffer).map_err(|error| TransportError::Io {
            operation: TransportOperation::Read,
            kind: error.kind(),
        })
    }

    fn write(&mut self, buffer: &[u8]) -> Result<usize, TransportError> {
        self.write_shared(buffer).map_err(|error| TransportError::Io {
            operation: TransportOperation::Write,
            kind: error.kind(),
        })
    }

    fn flush(&mut self) -> Result<(), TransportError> {
        self.flush_shared().map_err(|error| TransportError::Io {
            operation: TransportOperation::Flush,
            kind: error.kind(),
        })
    }

    fn shutdown(&self, how: Shutdown) -> Result<(), TransportError> {
        match how {
            Shutdown::Read => self.take_stdout(),
            Shutdown::Write => self.take_stdin(),
            Shutdown::Both => {
                self.kill_child().map_err(|error| TransportError::Io {
                    operation: TransportOperation::Shutdown,
                    kind: error.kind(),
                })?;
                self.take_stdin();
                self.take_stdout();
            }
        }
        Ok(())
    }

    fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        Err(TransportError::Io {
            operation: TransportOperation::LocalAddress,
            kind: io::ErrorKind::NotConnected,
        })
    }

    fn peer_addr(&self) -> Result<SocketAddr, TransportError> {
        Err(TransportError::Io {
            operation: TransportOperation::PeerAddress,
            kind: io::ErrorKind::NotConnected,
        })
    }
}

impl Read for ProxyCommandTransport {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        Transport::read(self, buffer).map_err(Into::into)
    }
}

impl Write for ProxyCommandTransport {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        Transport::write(self, buffer).map_err(Into::into)
    }

    fn flush(&mut self) -> io::Result<()> {
        Transport::flush(self).map_err(Into::into)
    }
}

impl Drop for ProxyCommandTransport {
    fn drop(&mut self) {
        let _ = self.stdin.get_mut().ok().and_then(Option::take);
        let _ = self.stdout.get_mut().ok().and_then(Option::take);
        if let Ok(child) = self.child.get_mut() {
            reap_child(child);
        }
    }
}

fn validate_program(program: &OsStr) -> Result<(), ProxyCommandError> {
    if program.is_empty() {
        return Err(ProxyCommandError::EmptyProgram);
    }
    if program.to_string_lossy().len() > MAX_PROXY_COMMAND_PROGRAM {
        return Err(ProxyCommandError::ProgramTooLong { max: MAX_PROXY_COMMAND_PROGRAM });
    }
    Ok(())
}

fn validate_argument(argument: &OsStr) -> Result<(), ProxyCommandError> {
    if argument.to_string_lossy().len() > MAX_PROXY_COMMAND_ARGUMENT {
        return Err(ProxyCommandError::ArgumentTooLong { max: MAX_PROXY_COMMAND_ARGUMENT });
    }
    Ok(())
}

fn reap_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::{Duration, timeout};

    fn echo_command() -> (OsString, Vec<OsString>) {
        #[cfg(windows)]
        {
            (
                std::env::var_os("ComSpec").unwrap_or_else(|| OsString::from("cmd.exe")),
                vec![OsString::from("/C"), OsString::from("more")],
            )
        }
        #[cfg(not(windows))]
        {
            (OsString::from("/bin/sh"), vec![OsString::from("-c"), OsString::from("cat")])
        }
    }

    fn stalled_command() -> (OsString, Vec<OsString>) {
        #[cfg(windows)]
        {
            (
                OsString::from("powershell.exe"),
                vec![
                    OsString::from("-NoProfile"),
                    OsString::from("-NonInteractive"),
                    OsString::from("-Command"),
                    OsString::from("$null = [Console]::In.ReadToEnd()"),
                ],
            )
        }
        #[cfg(not(windows))]
        {
            (
                OsString::from("/bin/sh"),
                vec![OsString::from("-c"), OsString::from("while IFS= read -r line; do :; done")],
            )
        }
    }

    #[test]
    fn termination_guard_reaps_the_running_child() {
        let (program, args) = stalled_command();
        let transport = ProxyCommandTransport::spawn(program, args).expect("spawn stalled child");
        let stream = ProxyCommandStream::new(transport);
        let child = Arc::clone(&stream.inner);
        drop(stream.termination_guard());
        assert!(
            child.child.lock().expect("child lock").try_wait().expect("child status").is_some()
        );
        drop(stream);
    }

    #[test]
    fn process_round_trips_and_closes_stdin() {
        let (program, args) = echo_command();
        let mut transport = ProxyCommandTransport::spawn(program, args).expect("spawn echo");
        transport.write_all(b"proxy-command\n").expect("write input");
        Write::flush(&mut transport).expect("flush input");
        transport.shutdown(Shutdown::Write).expect("close stdin");
        let mut response = Vec::new();
        transport.read_to_end(&mut response).expect("read echo");
        assert!(response.windows(b"proxy-command".len()).any(|window| window == b"proxy-command"));
        assert!(matches!(
            transport.local_addr(),
            Err(TransportError::Io {
                operation: TransportOperation::LocalAddress,
                kind: io::ErrorKind::NotConnected
            })
        ));
    }

    #[tokio::test]
    async fn async_process_stream_round_trips_bounded_io() {
        let (program, args) = echo_command();
        let transport = ProxyCommandTransport::spawn(program, args).expect("spawn echo");
        let mut stream = ProxyCommandStream::new(transport);
        stream.write_all(b"proxy-command\n").await.expect("write input");
        stream.flush().await.expect("flush input");
        let mut response = [0; 64];
        let length = timeout(Duration::from_secs(5), stream.read(&mut response))
            .await
            .expect("bounded read")
            .expect("read response");
        assert!(
            response[..length]
                .windows(b"proxy-command".len())
                .any(|window| { window == b"proxy-command" })
        );
        stream.shutdown().await.expect("shutdown process");
    }

    #[test]
    fn process_inputs_are_bounded_and_spawn_errors_are_typed() {
        assert!(matches!(
            ProxyCommandTransport::spawn("", std::iter::empty::<&str>()),
            Err(ProxyCommandError::EmptyProgram)
        ));
        assert!(matches!(
            ProxyCommandTransport::spawn(
                "echo",
                std::iter::repeat("arg").take(MAX_PROXY_COMMAND_ARGUMENTS + 1)
            ),
            Err(ProxyCommandError::TooManyArguments { max: MAX_PROXY_COMMAND_ARGUMENTS })
        ));
        assert!(matches!(
            ProxyCommandTransport::spawn(
                OsString::from("echo"),
                [OsString::from("x".repeat(MAX_PROXY_COMMAND_ARGUMENT + 1))]
            ),
            Err(ProxyCommandError::ArgumentTooLong { max: MAX_PROXY_COMMAND_ARGUMENT })
        ));
        assert!(matches!(
            ProxyCommandTransport::spawn(
                OsString::from("scoplen-command-that-does-not-exist"),
                std::iter::empty::<OsString>()
            ),
            Err(ProxyCommandError::Spawn { .. })
        ));
    }
}
