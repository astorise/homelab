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
        let services = [
            ("home-dns", "home-dns.exe"),
            ("home-http", "home-http.exe"),
            ("home-s3", "home-s3.exe"),
            ("home-oidc", "home-oidc.exe"),
        ];
        let missing_initial: Vec<_> = services
            .iter()
            .filter(|(_, exe)| !dst_bin.join(exe).exists())
            .collect();
        if !missing_initial.is_empty() {
            // Try copying from typical locations first
            for (pkg, exe) in services.iter() {
                let candidates = [
                    workspace_root.join("target").join("release").join(exe),
                    workspace_root
                        .join(pkg)
                        .join("target")
                        .join("release")
                        .join(exe),
                    manifest_path.join("bin").join(exe),
                ];
                for c in candidates.iter() {
                    if c.exists() {
                        let _ = std::fs::copy(c, dst_bin.join(exe));
                        break;
                    }
                }
            }

            // If still missing, build them now (best effort)
            let still_missing: Vec<_> = services
                .iter()
                .filter(|(_, exe)| !dst_bin.join(exe).exists())
                .collect();
            let still_need = !still_missing.is_empty();
            if still_need {
                println!("cargo:warning=Building service binaries (home-dns, home-http, home-s3, home-oidc) for bundling...");
                let mut cmd = std::process::Command::new("cargo");
                cmd.arg("build");
                for (pkg, _) in services.iter() {
                    cmd.arg("-p").arg(pkg);
                }
                cmd.arg("--release");
                let status = cmd
                    .current_dir(workspace_root)
                    .status()
                    .expect("failed to spawn cargo build for services");
                if status.success() {
                    for (_, exe) in services.iter() {
                        let _ = std::fs::copy(
                            workspace_root.join("target").join("release").join(exe),
                            dst_bin.join(exe),
                        );
                    }
                } else {
                    println!("cargo:warning=Service binaries not built; installer will not manage services.");
                }
            }
        }
    }

    // Prefer local files from src-tauri/bin only when explicitly allowed.
    // Default to OFF everywhere so stale developer binaries never override
    // freshly built service executables copied into resources/bin.
    let local_override = std::env::var("HOME_LAB_PREFER_LOCAL_BIN")
        .ok()
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false);
    if !local_override {
        println!(
            "cargo:warning=Skipping src-tauri/bin override. Set HOME_LAB_PREFER_LOCAL_BIN=1 to enable."
        );
    }

    // Local developer override (opt-in in CI, default on locally)
    let src_bin = manifest_path.join("bin");
    for name in [
        "home-dns.exe",
        "home-http.exe",
        "home-s3.exe",
        "home-oidc.exe",
    ] {
        let src = src_bin.join(name);
        let dst = dst_bin.join(name);
        println!("cargo:rerun-if-changed={}", src.display());
        if src.exists() && local_override {
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
        proto_dir.join("home_s3.proto"),
        proto_dir.join("home_oidc.proto"),
    ];
    let include_dirs = [proto_dir.clone()];
    for f in &files {
        println!("cargo:rerun-if-changed={}", f.display());
    }

    tonic_prost_build::configure()
        .build_client(true)
        .build_server(false)
        .compile_protos(&files, &include_dirs)
        .expect("failed to compile .proto files");
}
