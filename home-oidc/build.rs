fn main() {
    let proto_dir = std::path::PathBuf::from("proto");
    let proto = proto_dir.join("home_oidc.proto");

    println!("cargo:rerun-if-changed={}", proto.display());

    let protoc = protoc_bin_vendored::protoc_bin_path().expect("protoc not found");
    std::env::set_var("PROTOC", protoc);

    tonic_build::configure()
        .build_server(true)
        .build_client(false)
        .compile_protos(&[proto], &[proto_dir])
        .expect("failed to compile home_oidc.proto");
}
