// SPDX-License-Identifier: Apache-2.0
//! D-142 native passphrase-only age streams, without a Scoplen outer envelope.

use std::{
    fmt,
    io::{self, Read, Write},
    iter,
};

use age::{
    secrecy::{ExposeSecret as _, SecretString},
    stream::{StreamReader, StreamWriter},
};
use thiserror::Error;
use zeroize::Zeroizing;

/// Input-free failures of the optional native portable-export container.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PortableExportError {
    /// An export passphrase must contain at least one UTF-8 byte.
    #[error("the export passphrase is empty")]
    EmptyPassphrase,
    /// Only the standard binary age v1 passphrase recipient is supported.
    #[error("the export is not a supported age passphrase container")]
    InvalidContainer,
    /// The file's work factor exceeds the age library's normal bounded policy.
    #[error("the export requires an unsupported passphrase work factor")]
    UnsupportedCost,
    /// Header authentication or payload reading failed; no completion is established.
    #[error("the export could not be authenticated or read completely")]
    Decryption,
    /// Writing or finalizing the encrypted output failed.
    #[error("the export could not be written completely")]
    Encryption,
    /// The consumer returned before consuming the complete plaintext.
    #[error("the export plaintext has not been consumed completely")]
    UnconsumedPlaintext,
}

/// A nonempty exact UTF-8 passphrase, zeroized on drop and redacted in diagnostics.
///
/// Whitespace, embedded NUL and Unicode normalization forms are preserved exactly.
pub struct PortableExportPassphrase(SecretString);

impl PortableExportPassphrase {
    /// Take ownership of a passphrase without trimming or normalizing it.
    ///
    /// # Errors
    /// Rejects an empty string. Rust strings already guarantee valid UTF-8.
    pub fn new(passphrase: String) -> Result<Self, PortableExportError> {
        let passphrase = SecretString::from(passphrase);
        if passphrase.expose_secret().is_empty() {
            return Err(PortableExportError::EmptyPassphrase);
        }
        Ok(Self(passphrase))
    }
}

impl fmt::Debug for PortableExportPassphrase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PortableExportPassphrase([REDACTED])")
    }
}

/// A standard binary age passphrase encryption stream using the library's default cost.
///
/// This owns no file path and does not publish, rename or synchronize a file. The caller
/// must finish successfully before publishing output, then perform its own durable sync.
#[must_use = "finish the age writer before publishing an export"]
pub struct PortableExportWriter<W> {
    inner: StreamWriter<W>,
    failed: bool,
}

impl<W: Write> PortableExportWriter<W> {
    /// Start a binary age v1 stream with the library's calibrated passphrase recipient.
    ///
    /// # Errors
    /// Returns an input-free error if writing the age header fails.
    pub fn new(
        output: W,
        passphrase: &PortableExportPassphrase,
    ) -> Result<Self, PortableExportError> {
        let encryptor = age::Encryptor::with_user_passphrase(passphrase.0.clone());
        let inner = encryptor.wrap_output(output).map_err(|_| PortableExportError::Encryption)?;
        Ok(Self { inner, failed: false })
    }

    /// Write the authenticated final chunk, flush output and return the underlying writer.
    ///
    /// Dropping a writer, or merely calling `flush`, does not finish an export. A previous
    /// write/flush failure is sticky and cannot subsequently become a successful export.
    ///
    /// # Errors
    /// Rejects any earlier write failure, final-chunk failure or output flush failure.
    pub fn finish(self) -> Result<W, PortableExportError> {
        if self.failed {
            return Err(PortableExportError::Encryption);
        }
        let mut output = self.inner.finish().map_err(|_| PortableExportError::Encryption)?;
        output.flush().map_err(|_| PortableExportError::Encryption)?;
        Ok(output)
    }
}

impl<W: Write> Write for PortableExportWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.failed {
            return Err(stream_error(PortableExportError::Encryption));
        }
        self.inner
            .write(bytes)
            .inspect_err(|_| self.failed = true)
            .map_err(|_| stream_error(PortableExportError::Encryption))
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.failed {
            return Err(stream_error(PortableExportError::Encryption));
        }
        self.inner
            .flush()
            .inspect_err(|_| self.failed = true)
            .map_err(|_| stream_error(PortableExportError::Encryption))
    }
}

/// A passphrase-only age reader that authenticates completion explicitly.
///
/// `Read` can deliver valid prefixes before detecting a corrupt or missing final chunk.
/// Consumers may stage parsed entries inside one encrypted transaction, but must not commit
/// inventory, receipts or other side effects until parsing and [`Self::finish`] both succeed.
/// This stream does not implement the consumer's transaction or JSON EOF validation.
#[must_use = "consume the complete plaintext and finish before committing an import"]
pub struct PortableExportReader<R> {
    inner: StreamReader<R>,
    eof: bool,
    failed: bool,
}

impl<R: Read> PortableExportReader<R> {
    /// Open and authenticate an age passphrase header with the library's default cost bound.
    ///
    /// An opened header does not establish complete payload authentication.
    ///
    /// # Errors
    /// Rejects malformed/non-passphrase containers, excessive cost, wrong passphrases and I/O.
    pub fn new(
        input: R,
        passphrase: &PortableExportPassphrase,
    ) -> Result<Self, PortableExportError> {
        let decryptor = age::Decryptor::new(input).map_err(|error| decrypt_error(&error))?;
        if !decryptor.is_scrypt() {
            return Err(PortableExportError::InvalidContainer);
        }
        let identity = age::scrypt::Identity::new(passphrase.0.clone());
        let inner = decryptor
            .decrypt(iter::once(&identity as &dyn age::Identity))
            .map_err(|error| decrypt_error(&error))?;
        Ok(Self { inner, eof: false, failed: false })
    }

    /// Establish authenticated EOF after the consumer has processed all plaintext.
    ///
    /// This probes at most one byte and rejects unconsumed plaintext rather than silently
    /// discarding it. Empty-buffer reads do not count as EOF. Earlier read errors are sticky.
    /// The caller must also reject malformed or trailing JSON before committing its transaction.
    ///
    /// # Errors
    /// Rejects unconsumed plaintext, a previous error, truncation or final authentication failure.
    pub fn finish(mut self) -> Result<(), PortableExportError> {
        if self.failed {
            return Err(PortableExportError::Decryption);
        }
        if !self.eof {
            let mut probe = Zeroizing::new([0]);
            let read = self.read(&mut probe[..]).map_err(|_| PortableExportError::Decryption)?;
            if read != 0 {
                return Err(PortableExportError::UnconsumedPlaintext);
            }
        }
        Ok(())
    }
}

impl<R: Read> Read for PortableExportReader<R> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if self.failed {
            return Err(stream_error(PortableExportError::Decryption));
        }
        if bytes.is_empty() {
            return Ok(0);
        }
        if let Ok(read) = self.inner.read(bytes) {
            self.eof = read == 0;
            Ok(read)
        } else {
            self.failed = true;
            Err(stream_error(PortableExportError::Decryption))
        }
    }
}

fn stream_error(error: PortableExportError) -> io::Error {
    io::Error::other(error)
}

fn decrypt_error(error: &age::DecryptError) -> PortableExportError {
    match error {
        age::DecryptError::ExcessiveWork { .. } => PortableExportError::UnsupportedCost,
        age::DecryptError::InvalidHeader | age::DecryptError::UnknownFormat => {
            PortableExportError::InvalidContainer
        }
        _ => PortableExportError::Decryption,
    }
}
