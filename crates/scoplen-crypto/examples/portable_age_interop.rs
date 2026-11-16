// SPDX-License-Identifier: Apache-2.0
//! Synthetic standard-age interoperability pipe; never an inventory import transaction.

use std::io;

use scoplen_crypto::{
    PortableExportError, PortableExportPassphrase, PortableExportReader, PortableExportWriter,
};

fn run() -> Result<(), PortableExportError> {
    // Public test data shared with the independent Go reference, not a user credential.
    let passphrase =
        PortableExportPassphrase::new("\tD-142 synthetic e\u{301}\0\u{5bc6}\n".into())?;
    let operation = std::env::args().nth(1);
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    match operation.as_deref() {
        Some("encrypt") => {
            let mut writer = PortableExportWriter::new(&mut output, &passphrase)?;
            io::copy(&mut input, &mut writer).map_err(|_| PortableExportError::Encryption)?;
            writer.finish().map(|_| ())
        }
        Some("decrypt") => {
            let mut reader = PortableExportReader::new(&mut input, &passphrase)?;
            io::copy(&mut reader, &mut output).map_err(|_| PortableExportError::Decryption)?;
            reader.finish()
        }
        _ => Err(PortableExportError::InvalidContainer),
    }
}

fn main() {
    if run().is_err() {
        eprintln!("synthetic portable-age operation failed");
        std::process::exit(1);
    }
}
