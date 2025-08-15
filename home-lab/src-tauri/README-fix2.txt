# Fix build: tonic codegen + Endpoint keepalive

1) Dans src-tauri/Cargo.toml, active la feature `codegen` de tonic (ou retire `default-features=false`):
   [dependencies]
   tauri = { version = "2", features = ["tray-icon"] }
   tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
   tonic = { version = "0.11", features = ["transport","codegen"] }   # <- important
   prost = "0.12"
   serde = { version = "1", features = ["derive"] }
   anyhow = "1"
   tower = "0.5"

   [build-dependencies]
   tonic-build = "0.11"
   prost-build = "0.12"
   protoc-bin-vendored = "3"

2) Remplace src-tauri/src/lib.rs par celui de ce pack (suppression des méthodes http2_* non exposées).

3) Rebuild:
   cd home-lab/src-tauri
   cargo tauri build --bundles msi --verbose
