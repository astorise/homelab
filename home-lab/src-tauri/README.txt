# Tauri v2 Fix Pack (HomeDNS)
- src-tauri/build.rs: vendored protoc (tonic-build)
- src-tauri/proto/home_dns.proto: rrtype field
- src-tauri/src/lib.rs: Tauri v2 tray/menu + command `ping`
- src-tauri/src/main.rs: entry point
- src-tauri/tauri.conf.json: v2 schema; adjust `build.frontendDist` and `build.devUrl`

Required Cargo (src-tauri/Cargo.toml):
[dependencies]
tauri = { version = "2", features = ["tray-icon"] }
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
tonic = { version = "0.11", default-features = false, features = ["transport"] }
prost = "0.12"

[build-dependencies]
tonic-build = "0.11"
prost-build = "0.12"
protoc-bin-vendored = "3"