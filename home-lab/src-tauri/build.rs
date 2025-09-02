fn main() {
    // Conserve la génération Tauri
    tauri_build::build();

    // --- Génération gRPC (Prost/Tonic) ---
    // (vendored protoc pour éviter d'installer protoc sur la machine)
    let protoc = protoc_bin_vendored::protoc_bin_path().expect("protoc introuvable");
    std::env::set_var("PROTOC", protoc);

    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let proto_dir = std::path::Path::new(&manifest_dir).join("proto");

    let files = [
        proto_dir.join("home_dns.proto"),
        proto_dir.join("home_http.proto"),
    ];

    // Rebuild si les .proto changent
    for f in &files {
        println!("cargo:rerun-if-changed={}", f.display());
    }

    tonic_build::configure()
        .build_server(false) // client uniquement côté app Tauri
        .compile(
            &files.iter().map(|p| p.as_path()).collect::<Vec<_>>(),
            &[proto_dir.as_path()],
        )
        .expect("échec compilation des .proto");

    // --- Préparer les binaires services pour le bundling (NSIS/MSI) ---
    // Copie src-tauri/bin/*.exe -> src-tauri/resources/bin/
    let src_bin = std::path::Path::new(&manifest_dir).join("bin");
    let dst_bin = std::path::Path::new(&manifest_dir).join("resources").join("bin");
    let _ = std::fs::create_dir_all(&dst_bin);
    for name in ["home-dns.exe", "home-http.exe"] {
        let src = src_bin.join(name);
        let dst = dst_bin.join(name);
        println!("cargo:rerun-if-changed={}", src.display());
        if src.exists() {
            let _ = std::fs::copy(&src, &dst);
        }
    }
}

