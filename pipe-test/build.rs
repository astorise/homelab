fn main() {
    let proto_dir = std::path::Path::new("../home-lab/src-tauri/proto");
    if let Ok(pb) = protoc_bin_vendored::protoc_bin_path() {
        std::env::set_var("PROTOC", pb);
    }
    let out = tonic_build::configure();
    out.compile(
        &[
            proto_dir.join("home_dns.proto"),
            proto_dir.join("home_http.proto"),
        ],
        &[proto_dir],
    )
    .expect("compile protos");
}
