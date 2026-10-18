// SPDX-License-Identifier: Apache-2.0

use std::{env, path::PathBuf};

fn main() {
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest path"));
    let proto_root = manifest_dir.join("proto");
    let gateway = proto_root.join("spl/gateway/v1/control.proto");
    let agent = proto_root.join("spl/agent/v1/agent.proto");
    let descriptor = PathBuf::from(env::var_os("OUT_DIR").expect("build output path"))
        .join("scoplen-internal-descriptor.bin");

    println!("cargo:rerun-if-changed={}", gateway.display());
    println!("cargo:rerun-if-changed={}", agent.display());

    let mut prost = prost_build::Config::new();
    prost.protoc_executable(protoc_bin_vendored::protoc_bin_path().expect("bundled protoc"));
    prost.file_descriptor_set_path(descriptor);
    let tonic = tonic_build::configure()
        .build_client(true)
        .build_server(true)
        .client_mod_attribute(".", "#[allow(clippy::all, clippy::pedantic)]")
        .server_mod_attribute(".", "#[allow(clippy::all, clippy::pedantic)]");
    prost.service_generator(tonic.service_generator());
    prost
        .compile_protos(&[gateway, agent], std::slice::from_ref(&proto_root))
        .expect("internal protobuf contracts compile");
}
