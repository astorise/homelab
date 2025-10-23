fn main() {
    let proto_dir = std::path::Path::new("../home-lab/src-tauri/proto");
    if let Ok(pb) = protoc_bin_vendored::protoc_bin_path() {
        std::env::set_var("PROTOC", pb);
    }
    let include_dirs = [proto_dir.to_path_buf()];
    let protos = [
        proto_dir.join("home_dns.proto"),
        proto_dir.join("home_http.proto"),
    ];

    tonic_prost_build::configure()
        .build_client(true)
        .build_server(false)
        .compile_protos(&protos, &include_dirs)
        .expect("compile protos");
}
