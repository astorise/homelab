fn main() {
    // Ensure resources exist before tauri_build::build()
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let manifest_path = std::path::Path::new(&manifest_dir);
    let workspace_root = manifest_path.parent().unwrap_or(manifest_path);

    // Prepare service binaries for bundling (NSIS/MSI)
    let dst_bin = manifest_path.join("resources").join("bin");
    let _ = std::fs::create_dir_all(&dst_bin);

    // If missing, try to build the services and/or copy from common target locations
    #[cfg(target_os = "windows")]
    {
        let need_dns = !dst_bin.join("home-dns.exe").exists();
        let need_http = !dst_bin.join("home-http.exe").exists();
        if need_dns || need_http {
            // Try copying from typical locations first
            for (name, rel) in [
                ("home-dns.exe", "home-dns.exe"),
                ("home-http.exe", "home-http.exe"),
            ] {
                let candidates = [
                    workspace_root.join("target").join("release").join(rel),
                    workspace_root
                        .join("home-dns")
                        .join("target")
                        .join("release")
                        .join(rel),
                    workspace_root
                        .join("home-http")
                        .join("target")
                        .join("release")
                        .join(rel),
                    manifest_path.join("bin").join(rel),
                ];
                for c in candidates.iter() {
                    if c.exists() {
                        let _ = std::fs::copy(c, dst_bin.join(name));
                        break;
                    }
                }
            }

            // If still missing, build them now (best effort)
            let still_need =
                !dst_bin.join("home-dns.exe").exists() || !dst_bin.join("home-http.exe").exists();
            if still_need {
                println!(
                    "cargo:warning=Building service binaries (home-dns, home-http) for bundling..."
                );
                let status = std::process::Command::new("cargo")
                    .args(["build", "-p", "home-dns", "-p", "home-http", "--release"])
                    .current_dir(workspace_root)
                    .status()
                    .expect("failed to spawn cargo build for services");
                if status.success() {
                    let _ = std::fs::copy(
                        workspace_root
                            .join("target")
                            .join("release")
                            .join("home-dns.exe"),
                        dst_bin.join("home-dns.exe"),
                    );
                    let _ = std::fs::copy(
                        workspace_root
                            .join("target")
                            .join("release")
                            .join("home-http.exe"),
                        dst_bin.join("home-http.exe"),
                    );
                } else {
                    println!("cargo:warning=Service binaries not built; installer will not manage services.");
                }
            }
        }
    }

    // Always prefer files from src-tauri/bin if present (developer override)
    let src_bin = manifest_path.join("bin");
    for name in ["home-dns.exe", "home-http.exe"] {
        let src = src_bin.join(name);
        let dst = dst_bin.join(name);
        println!("cargo:rerun-if-changed={}", src.display());
        if src.exists() {
            let _ = std::fs::copy(&src, &dst);
        }
    }

    // Proceed with tauri build (reads tauri.conf.json and resources)
    tauri_build::build();

    // gRPC client codegen for the app (prost/tonic)
    let protoc = protoc_bin_vendored::protoc_bin_path().expect("protoc not found");
    std::env::set_var("PROTOC", protoc);

    let proto_dir = std::path::Path::new(&manifest_dir).join("proto");
    let files = [
        proto_dir.join("home_dns.proto"),
        proto_dir.join("home_http.proto"),
    ];
    let include_dirs = [proto_dir.clone()];
    for f in &files {
        println!("cargo:rerun-if-changed={}", f.display());
    }

    tonic_prost_build::configure()
        .build_client(false)
        .build_server(false) // messages only for RPC transport
        .compile_protos(&files, &include_dirs)
        .expect("failed to compile .proto files");
}
