#![allow(unsafe_code)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Embed build metadata for traceability
    let sha = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".into());
    let tag = std::process::Command::new("git")
        .args(["describe", "--tags", "--always"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| sha.clone());
    let when = chrono::Utc::now().to_rfc3339();
    println!("cargo:rustc-env=BUILD_GIT_SHA={}", sha);
    println!("cargo:rustc-env=BUILD_GIT_TAG={}", tag);
    println!("cargo:rustc-env=BUILD_TIME={}", when);
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    // Force l'utilisation du protoc embarqué (utile en CI/Windows)
    unsafe {
        std::env::set_var("PROTOC", protoc);
    }

    let proto_dir = std::path::PathBuf::from("proto");
    let proto = proto_dir.join("home_http.proto");
    println!("cargo:rerun-if-changed={}", proto.display());
    println!("cargo:rerun-if-changed={}", proto_dir.display());

    tonic_prost_build::configure()
        .build_server(true)
        .compile_protos(&[proto], &[proto_dir])?;
    Ok(())
}
