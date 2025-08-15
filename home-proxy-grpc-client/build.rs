#![allow(unsafe_code)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    unsafe { std::env::set_var("PROTOC", protoc); }
    tonic_build::configure()
        .build_client(true)
        .build_server(false)
        .compile(&["proto/home_proxy.proto"], &["proto"])?;
    println!("cargo:rerun-if-changed=proto/home_proxy.proto");
    println!("cargo:rerun-if-changed=proto");
    Ok(())
}
