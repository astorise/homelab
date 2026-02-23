fn main() {
    let sha = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let tag = std::process::Command::new("git")
        .args(["describe", "--tags", "--always"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| sha.clone());
    println!("cargo:rustc-env=BUILD_GIT_SHA={sha}");
    println!("cargo:rustc-env=BUILD_GIT_TAG={tag}");

    let proto_dir = std::path::PathBuf::from("proto");
    let proto = proto_dir.join("home_oidc.proto");

    println!("cargo:rerun-if-changed={}", proto.display());

    let protoc = protoc_bin_vendored::protoc_bin_path().expect("protoc not found");
    std::env::set_var("PROTOC", protoc);

    tonic_prost_build::configure()
        .build_server(true)
        .build_client(false)
        .compile_protos(&[proto], &[proto_dir])
        .expect("failed to compile home_oidc.proto");
}
