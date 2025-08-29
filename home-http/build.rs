#![allow(unsafe_code)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    // Force l'utilisation du protoc embarqué (utile en CI/Windows)
    unsafe { std::env::set_var("PROTOC", protoc); }

tonic_build::configure()
    .build_client(true)
    .build_server(true)
    .compile_protos(&["proto/home_http.proto"], &["proto"])?;

    println!("cargo:rerun-if-changed=proto/home_http.proto");
    println!("cargo:rerun-if-changed=proto");
    Ok(())
}
