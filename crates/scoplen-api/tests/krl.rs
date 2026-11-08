// SPDX-License-Identifier: Apache-2.0

use scoplen_api::krl::{
    KrlCodecError as Error, MAX_USER_CA_KRL_BYTES, MAX_USER_CA_KRL_SERIALS,
    USER_CA_KRL_CONTENT_TYPE, UserCaKrl,
};
use scoplen_test_vectors::VectorDocument;
use serde_json::Value;

const CA: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3B1Ea";

fn hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn independent_vectors_exercise_the_public_codec() {
    let document =
        VectorDocument::parse_str(include_str!("../../../vectors/user-ca-krl.json")).unwrap();
    assert!(document.vectors.len() > 50);
    for vector in document.vectors {
        let recipe: Value = serde_json::from_str(&vector.input).unwrap();
        let ca = recipe["ca_public_key"].as_str().unwrap();
        match vector.kind.as_str() {
            "user_ca.krl.bytes" => {
                let serials: Vec<u64> = recipe["serials"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|value| value.as_str().unwrap().parse().unwrap())
                    .collect();
                let snapshot = UserCaKrl::new(
                    ca,
                    recipe["version"].as_str().unwrap().parse().unwrap(),
                    recipe["generated_at_seconds"].as_str().unwrap().parse().unwrap(),
                    &serials,
                )
                .unwrap();
                let expected = hex(&vector.expected);
                assert_eq!(snapshot.to_bytes().unwrap(), expected, "{}", vector.id);
                assert_eq!(
                    UserCaKrl::from_bytes(&expected, ca).unwrap(),
                    snapshot,
                    "{}",
                    vector.id
                );
                assert_eq!(snapshot.ca_public_key(), ca);
                assert_eq!(snapshot.revoked_serials(), serials);
                assert_eq!(snapshot.to_bytes().unwrap(), expected);
            }
            "user_ca.krl.reject" => {
                assert!(
                    UserCaKrl::from_bytes(&hex(recipe["hex"].as_str().unwrap()), ca).is_err(),
                    "{}",
                    vector.id
                );
            }
            "user_ca.krl.bound" => {
                if let Some(count) = recipe["count"].as_u64() {
                    let serials: Vec<_> = (1..=count).collect();
                    if vector.expected == "accepted" {
                        let snapshot = UserCaKrl::new(ca, 1, 0, &serials).unwrap();
                        let encoded = snapshot.to_bytes().unwrap();
                        assert_eq!(encoded.len(), 800_113);
                        assert_eq!(UserCaKrl::from_bytes(&encoded, ca).unwrap(), snapshot);
                    } else {
                        assert_eq!(
                            UserCaKrl::new(ca, 1, 0, &serials),
                            Err(Error::TooManySerials),
                            "{}",
                            vector.id
                        );
                        // Extend an independently well-shaped serial subsection beyond the cap.
                        let mut encoded =
                            UserCaKrl::new(ca, 1, 0, &serials[..MAX_USER_CA_KRL_SERIALS])
                                .unwrap()
                                .to_bytes()
                                .unwrap();
                        encoded.extend_from_slice(&count.to_be_bytes());
                        let section_len = u32::try_from(encoded.len() - 49).unwrap();
                        encoded[45..49].copy_from_slice(&section_len.to_be_bytes());
                        let serial_len = u32::try_from(count * 8).unwrap();
                        encoded[109..113].copy_from_slice(&serial_len.to_be_bytes());
                        assert_eq!(UserCaKrl::from_bytes(&encoded, ca), Err(Error::TooManySerials));
                    }
                } else {
                    let bytes = usize::try_from(recipe["bytes"].as_u64().unwrap()).unwrap();
                    let mut input = UserCaKrl::new(ca, 1, 0, &[]).unwrap().to_bytes().unwrap();
                    input.resize(bytes, 0);
                    let expected = if bytes > MAX_USER_CA_KRL_BYTES {
                        Error::InputTooLarge
                    } else {
                        Error::InvalidFormat
                    };
                    assert_eq!(UserCaKrl::from_bytes(&input, ca), Err(expected), "{}", vector.id);
                }
            }
            other => panic!("unexpected KRL vector kind {other}"),
        }
    }
}

#[test]
fn constructor_refuses_noncanonical_input_without_sorting_or_deduplication() {
    for serials in [&[0][..], &[2, 1], &[1, 1], &[1, 0]] {
        assert_eq!(UserCaKrl::new(CA, 1, 0, serials), Err(Error::InvalidSerials));
    }
    assert_eq!(UserCaKrl::new(CA, 0, 0, &[]), Err(Error::InvalidHeader));
    let empty = UserCaKrl::new(CA, 1, 0, &[]).unwrap();
    assert_eq!(empty.version(), 1);
    assert_eq!(empty.generated_at_seconds(), 0);
    assert_eq!(empty.to_bytes().unwrap().len(), 44);
    for invalid in ["", "ssh-ed25519 invalid", &format!("{CA} comment"), &format!("{CA}\n")] {
        assert_eq!(UserCaKrl::new(invalid, 1, 0, &[]), Err(Error::InvalidCa));
        assert_eq!(
            UserCaKrl::from_bytes(&empty.to_bytes().unwrap(), invalid),
            Err(Error::InvalidCa)
        );
    }
}

#[test]
fn http_metadata_is_exact_and_diagnostics_do_not_echo_input() {
    let snapshot = UserCaKrl::new(CA, u64::MAX, u64::MAX, &[1, u64::MAX]).unwrap();
    let input = snapshot.to_bytes().unwrap();
    let metadata =
        [Some(USER_CA_KRL_CONTENT_TYPE), Some("no-store"), Some("no-cache"), Some("fixture")];
    let parse = |headers: [Option<&str>; 4]| {
        UserCaKrl::from_http_bytes(&input, CA, headers[0], headers[1], headers[2], headers[3])
    };
    assert_eq!(parse(metadata).unwrap(), snapshot);
    for index in 0..4 {
        for invalid in [None, Some("")] {
            let mut headers = metadata;
            headers[index] = invalid;
            assert_eq!(parse(headers), Err(Error::HttpMetadata));
        }
    }
    for (index, invalid) in [
        (0, "application/json"),
        (0, "application/octet-stream; charset=utf-8"),
        (1, "no-store, private"),
        (2, "max-age=0"),
    ] {
        let mut headers = metadata;
        headers[index] = Some(invalid);
        assert_eq!(parse(headers), Err(Error::HttpMetadata));
    }
    for value in
        [format!("{snapshot:?}"), Error::InvalidCa.to_string(), Error::CaMismatch.to_string()]
    {
        assert!(!value.contains(CA));
        assert!(!value.contains("AAAAC3"));
    }
}

#[test]
fn every_truncated_nonempty_snapshot_is_refused_except_its_valid_empty_header() {
    let bytes = UserCaKrl::new(CA, 3, 123, &[1, 2]).unwrap().to_bytes().unwrap();
    for len in 0..bytes.len() {
        if len == 44 {
            let empty = UserCaKrl::from_bytes(&bytes[..len], CA).unwrap();
            assert_eq!(empty.revoked_serials(), &[] as &[u64]);
        } else {
            assert!(UserCaKrl::from_bytes(&bytes[..len], CA).is_err(), "length {len}");
        }
    }
}

#[test]
fn real_openssh_queries_bytes_from_the_public_codec() {
    use std::{fs, process::Command};

    let parent = std::env::temp_dir();
    let directory = parent.join(format!("scoplen-krl-openssh-{}", uuid::Uuid::now_v7()));
    fs::create_dir(&directory).unwrap();
    let run = |args: &[&str]| {
        Command::new("ssh-keygen")
            .args(args)
            .current_dir(&directory)
            .output()
            .expect("ssh-keygen must be installed for D-141 interoperability")
    };
    for key in ["ca", "other-ca", "subject"] {
        assert!(run(&["-q", "-t", "ed25519", "-N", "", "-f", key]).status.success());
    }
    for (name, ca, serial) in
        [("revoked", "ca", "7"), ("fresh", "ca", "8"), ("other-team", "other-ca", "7")]
    {
        assert!(
            run(&[
                "-q",
                "-s",
                ca,
                "-I",
                "scoplen-krl-fixture",
                "-n",
                "fixture",
                "-V",
                "-1m:+5m",
                "-z",
                serial,
                "subject.pub",
            ])
            .status
            .success()
        );
        fs::rename(directory.join("subject-cert.pub"), directory.join(format!("{name}.pub")))
            .unwrap();
    }
    let ca_line = fs::read_to_string(directory.join("ca.pub")).unwrap();
    let ca = ca_line.split_whitespace().take(2).collect::<Vec<_>>().join(" ");
    for (file, serials) in [("empty.krl", &[][..]), ("revoked.krl", &[7][..])] {
        let snapshot = UserCaKrl::new(&ca, 2, 1_762_646_400, serials).unwrap();
        fs::write(directory.join(file), snapshot.to_bytes().unwrap()).unwrap();
        for name in ["revoked", "fresh", "other-team"] {
            let query = run(&["-Q", "-f", file, &format!("{name}.pub")]);
            let revoked = file == "revoked.krl" && name == "revoked";
            assert_eq!(query.status.code(), Some(i32::from(revoked)), "{file}/{name}");
            if revoked {
                assert!(String::from_utf8(query.stdout).unwrap().contains("REVOKED"));
            }
        }
        assert!(run(&["-Q", "-f", file, "subject.pub"]).status.success());
    }
    assert_eq!(directory.parent(), Some(parent.as_path()));
    assert!(directory.file_name().unwrap().to_str().unwrap().starts_with("scoplen-krl-openssh-"));
    fs::remove_dir_all(directory).unwrap();
}
