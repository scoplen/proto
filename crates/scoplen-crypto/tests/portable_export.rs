// SPDX-License-Identifier: Apache-2.0
#![cfg(feature = "portable-export")]

use std::{
    cell::Cell,
    io::{self, Cursor, Read, Write},
    iter,
    rc::Rc,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use scoplen_crypto::{
    PortableExportError, PortableExportPassphrase, PortableExportReader, PortableExportWriter,
};
use scoplen_test_vectors::VectorDocument;
use serde::Deserialize;

const PASSPHRASE: &str = "\tD-142 synthetic e\u{301}\0\u{5bc6}\n";
const IO_DIAGNOSTIC: &str = "synthetic underlying private I/O context";
const CHUNK: usize = 65_536;

fn passphrase() -> PortableExportPassphrase {
    PortableExportPassphrase::new(PASSPHRASE.into()).unwrap()
}

// Low cost applies only to synthetic read fixtures. Production writes use the public API.
fn encrypted_fixture(plaintext: &[u8]) -> Vec<u8> {
    let mut recipient = age::scrypt::Recipient::new(PASSPHRASE.to_owned().into());
    recipient.set_work_factor(4);
    let encryptor =
        age::Encryptor::with_recipients(iter::once(&recipient as &dyn age::Recipient)).unwrap();
    let mut writer = encryptor.wrap_output(Vec::new()).unwrap();
    writer.write_all(plaintext).unwrap();
    writer.finish().unwrap()
}

fn assert_payload_failure(ciphertext: &[u8]) {
    let mut reader = PortableExportReader::new(ciphertext, &passphrase()).unwrap();
    let mut output = Vec::new();
    let error = reader.read_to_end(&mut output).unwrap_err();
    assert_eq!(error.to_string(), PortableExportError::Decryption.to_string());
    assert_eq!(reader.finish(), Err(PortableExportError::Decryption));
}

#[test]
fn independent_go_age_fixtures_decrypt_through_the_public_api_to_authenticated_eof() {
    #[derive(Deserialize)]
    struct Input {
        passphrase: String,
        ciphertext_base64: String,
    }
    let document =
        VectorDocument::from_bytes(include_bytes!("../../../vectors/portable-age.json")).unwrap();
    assert_eq!(document.vectors.len(), 3);
    for vector in document.vectors {
        assert_eq!(vector.kind, "crypto.portable-age.decrypt");
        let input: Input = serde_json::from_str(&vector.input).unwrap();
        let passphrase = PortableExportPassphrase::new(input.passphrase).unwrap();
        let ciphertext = STANDARD.decode(input.ciphertext_base64).unwrap();
        let mut reader = PortableExportReader::new(ciphertext.as_slice(), &passphrase).unwrap();
        let mut plaintext = Vec::new();
        reader.read_to_end(&mut plaintext).unwrap();
        reader.finish().unwrap();
        assert_eq!(plaintext, STANDARD.decode(vector.expected).unwrap(), "{}", vector.id);
    }
}

#[test]
fn production_writer_round_trips_empty_exact_chunk_and_multichunk_payloads() {
    for size in [0, CHUNK, CHUNK * 2 + 17] {
        let plaintext = vec![0xa5; size];
        let mut writer = PortableExportWriter::new(Vec::new(), &passphrase()).unwrap();
        writer.write_all(&plaintext).unwrap();
        let ciphertext = writer.finish().unwrap();
        assert!(ciphertext.starts_with(b"age-encryption.org/v1\n-> scrypt "));
        let mut reader = PortableExportReader::new(ciphertext.as_slice(), &passphrase()).unwrap();
        let mut actual = vec![0; size];
        reader.read_exact(&mut actual).unwrap();
        // finish must observe authenticated EOF even without a preceding zero-byte read.
        reader.finish().unwrap();
        assert_eq!(actual, plaintext);
    }
}

#[test]
fn passphrases_are_nonempty_exact_utf8_and_redacted() {
    assert_eq!(
        PortableExportPassphrase::new(String::new()).err(),
        Some(PortableExportError::EmptyPassphrase)
    );
    assert!(PortableExportPassphrase::new(" \t\n".into()).is_ok());
    assert!(PortableExportPassphrase::new("\0".into()).is_ok());
    assert_eq!(format!("{:?}", passphrase()), "PortableExportPassphrase([REDACTED])");
    let ciphertext = encrypted_fixture(b"synthetic payload");
    for wrong in [
        "wrong synthetic passphrase".to_owned(),
        PASSPHRASE.trim().to_owned(),
        PASSPHRASE.replace("e\u{301}", "\u{e9}"),
        PASSPHRASE.replace('\0', ""),
    ] {
        let wrong = PortableExportPassphrase::new(wrong).unwrap();
        assert_eq!(
            PortableExportReader::new(ciphertext.as_slice(), &wrong).err(),
            Some(PortableExportError::Decryption)
        );
    }
}

#[test]
fn empty_reads_and_decrypted_prefixes_do_not_establish_consumption() {
    let ciphertext = encrypted_fixture(b"synthetic payload");
    let mut reader = PortableExportReader::new(ciphertext.as_slice(), &passphrase()).unwrap();
    assert_eq!(reader.read(&mut []).unwrap(), 0);
    assert_eq!(reader.finish(), Err(PortableExportError::UnconsumedPlaintext));

    let mut reader = PortableExportReader::new(ciphertext.as_slice(), &passphrase()).unwrap();
    reader.read_exact(&mut [0; 1]).unwrap();
    assert_eq!(reader.finish(), Err(PortableExportError::UnconsumedPlaintext));
}

#[test]
fn tampering_truncation_and_trailing_ciphertext_reject_late_completion() {
    let plaintext = vec![0xa5; CHUNK + 17];
    let ciphertext = encrypted_fixture(&plaintext);
    for omitted in [1, 16, 17 + 16] {
        assert_payload_failure(&ciphertext[..ciphertext.len() - omitted]);
    }
    let mut altered = ciphertext.clone();
    *altered.last_mut().unwrap() ^= 1;
    let mut reader = PortableExportReader::new(altered.as_slice(), &passphrase()).unwrap();
    let mut prefix = vec![0; CHUNK];
    reader.read_exact(&mut prefix).unwrap();
    assert_eq!(prefix, plaintext[..CHUNK]);
    assert_eq!(reader.finish(), Err(PortableExportError::Decryption));
    assert_payload_failure(&altered);

    let mut trailing = ciphertext.clone();
    trailing.extend_from_slice(b"trailing invalid ciphertext");
    assert_payload_failure(&trailing);

    let mut altered_header = ciphertext;
    // The first salt character is valid base64 but authenticates a different header.
    let salt = b"age-encryption.org/v1\n-> scrypt ".len();
    altered_header[salt] = if altered_header[salt] == b'A' { b'B' } else { b'A' };
    assert_eq!(
        PortableExportReader::new(altered_header.as_slice(), &passphrase()).err(),
        Some(PortableExportError::Decryption)
    );
}

#[test]
fn malformed_nonpassphrase_armor_and_excessive_cost_are_rejected() {
    for input in [b"".as_slice(), b"not age", b"-----BEGIN AGE ENCRYPTED FILE-----\n"] {
        assert!(PortableExportReader::new(input, &passphrase()).is_err());
    }
    let identity = age::x25519::Identity::generate();
    let recipient = identity.to_public();
    let encryptor =
        age::Encryptor::with_recipients(iter::once(&recipient as &dyn age::Recipient)).unwrap();
    let ciphertext = encryptor.wrap_output(Vec::new()).unwrap().finish().unwrap();
    assert_eq!(
        PortableExportReader::new(ciphertext.as_slice(), &passphrase()).err(),
        Some(PortableExportError::InvalidContainer)
    );

    let mut excessive = encrypted_fixture(b"synthetic");
    let work = excessive.windows(3).position(|bytes| bytes == b" 4\n").unwrap();
    excessive.splice(work..work + 3, b" 63\n".iter().copied());
    assert_eq!(
        PortableExportReader::new(excessive.as_slice(), &passphrase()).err(),
        Some(PortableExportError::UnsupportedCost)
    );
}

struct ObservedReader {
    inner: Cursor<Vec<u8>>,
    maximum: Rc<Cell<usize>>,
    failure: Rc<Cell<bool>>,
}

impl Read for ObservedReader {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.maximum.set(self.maximum.get().max(bytes.len()));
        if self.failure.get() {
            return Err(io::Error::other(IO_DIAGNOSTIC));
        }
        self.inner.read(bytes)
    }
}

#[test]
fn multichunk_reads_are_bounded_without_a_whole_document_plaintext_buffer() {
    let maximum = Rc::new(Cell::new(0));
    let input = ObservedReader {
        inner: Cursor::new(encrypted_fixture(&vec![0xa5; CHUNK * 3 + 17])),
        maximum: Rc::clone(&maximum),
        failure: Rc::new(Cell::new(false)),
    };
    let mut reader = PortableExportReader::new(input, &passphrase()).unwrap();
    let mut bytes = [0; 997];
    let mut total = 0;
    loop {
        let count = reader.read(&mut bytes).unwrap();
        if count == 0 {
            break;
        }
        assert!(bytes[..count].iter().all(|byte| *byte == 0xa5));
        total += count;
    }
    reader.finish().unwrap();
    assert_eq!(total, CHUNK * 3 + 17);
    assert!(maximum.get() <= CHUNK + 16);
}

#[test]
fn underlying_read_errors_are_redacted_and_sticky() {
    let failure = Rc::new(Cell::new(false));
    let input = ObservedReader {
        inner: Cursor::new(encrypted_fixture(b"synthetic")),
        maximum: Rc::new(Cell::new(0)),
        failure: Rc::clone(&failure),
    };
    let mut reader = PortableExportReader::new(input, &passphrase()).unwrap();
    failure.set(true);
    let error = reader.read(&mut [0; 16]).unwrap_err();
    assert!(!format!("{error:?}").contains(IO_DIAGNOSTIC));
    assert!(!error.to_string().contains(PASSPHRASE));
    failure.set(false);
    assert!(reader.read(&mut [0; 16]).is_err());
    assert_eq!(reader.finish(), Err(PortableExportError::Decryption));

    let input = ObservedReader {
        inner: Cursor::new(Vec::new()),
        maximum: Rc::new(Cell::new(0)),
        failure: Rc::new(Cell::new(true)),
    };
    let error = PortableExportReader::new(input, &passphrase()).err().unwrap();
    assert!(!format!("{error:?}: {error}").contains(IO_DIAGNOSTIC));
}

struct FailingWriter {
    write_failure: Rc<Cell<bool>>,
    flush_failure: Rc<Cell<bool>>,
}

impl Write for FailingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.write_failure.get() {
            return Err(io::Error::other(IO_DIAGNOSTIC));
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.flush_failure.get() {
            return Err(io::Error::other(IO_DIAGNOSTIC));
        }
        Ok(())
    }
}

#[test]
fn writer_header_stream_final_chunk_and_flush_failures_cannot_be_successful() {
    for phase in ["header", "stream", "final", "flush", "finish-flush"] {
        let write_failure = Rc::new(Cell::new(phase == "header"));
        let flush_failure = Rc::new(Cell::new(false));
        let output = FailingWriter {
            write_failure: Rc::clone(&write_failure),
            flush_failure: Rc::clone(&flush_failure),
        };
        let result = PortableExportWriter::new(output, &passphrase());
        if phase == "header" {
            assert_eq!(result.err(), Some(PortableExportError::Encryption));
            continue;
        }
        let mut writer = result.unwrap();
        match phase {
            "stream" => {
                write_failure.set(true);
                let error = writer.write_all(&vec![0xa5; CHUNK + 1]).unwrap_err();
                assert!(!format!("{error:?}: {error}").contains(IO_DIAGNOSTIC));
                write_failure.set(false);
                assert!(writer.write(b"later").is_err());
            }
            "final" => {
                writer.write_all(b"synthetic").unwrap();
                write_failure.set(true);
            }
            "flush" => {
                flush_failure.set(true);
                let error = writer.flush().unwrap_err();
                assert!(!format!("{error:?}: {error}").contains(IO_DIAGNOSTIC));
                flush_failure.set(false);
            }
            "finish-flush" => flush_failure.set(true),
            _ => unreachable!(),
        }
        assert_eq!(writer.finish().err(), Some(PortableExportError::Encryption), "{phase}");
    }
}

#[test]
fn flushing_and_dropping_a_writer_does_not_publish_a_complete_export() {
    let mut ciphertext = Vec::new();
    {
        let mut writer = PortableExportWriter::new(&mut ciphertext, &passphrase()).unwrap();
        writer.write_all(b"synthetic payload").unwrap();
        writer.flush().unwrap();
    }
    assert_payload_failure(&ciphertext);
}
