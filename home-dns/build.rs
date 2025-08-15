#![allow(unsafe_code)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    unsafe { std::env::set_var("PROTOC", protoc); }

    tonic_build::configure()
        .build_client(true)
        .build_server(true)
        .compile(&["proto/home_dns.proto"], &["proto"])?;
    println!("cargo:rerun-if-changed=proto/home_dns.proto");
    println!("cargo:rerun-if-changed=proto");
    Ok(())
}
