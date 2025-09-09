#![allow(unsafe_code)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Embed build metadata for traceability
    let sha = std::process::Command::new("git").args(["rev-parse", "--short", "HEAD"]).output()
        .ok().and_then(|o| String::from_utf8(o.stdout).ok()).map(|s| s.trim().to_string()).unwrap_or_else(|| "unknown".into());
    let tag = std::process::Command::new("git").args(["describe", "--tags", "--always"]).output()
        .ok().and_then(|o| String::from_utf8(o.stdout).ok()).map(|s| s.trim().to_string()).unwrap_or_else(|| sha.clone());
    let when = chrono::Utc::now().to_rfc3339();
    println!("cargo:rustc-env=BUILD_GIT_SHA={}", sha);
    println!("cargo:rustc-env=BUILD_GIT_TAG={}", tag);
    println!("cargo:rustc-env=BUILD_TIME={}", when);
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    // Force l'utilisation du protoc embarqué (utile en CI/Windows)
    unsafe { std::env::set_var("PROTOC", protoc); }

tonic_build::configure()
    .build_client(true)
    .build_server(true)
    .compile(&["proto/home_http.proto"], &["proto"])?;

    println!("cargo:rerun-if-changed=proto/home_http.proto");
    println!("cargo:rerun-if-changed=proto");
    Ok(())
}
