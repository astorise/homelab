use std::env;
use std::fs;
use std::path::Path;

fn main() {
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");
    let dest = Path::new(&out_dir).join("wsl-image.tar");
    let image_path = env::var("WSL_IMAGE_ARCHIVE")
        .expect("WSL_IMAGE_ARCHIVE environment variable not set");
    fs::copy(&image_path, &dest).expect("failed to copy image archive");
    println!("cargo:rustc-env=WSL_IMAGE_PATH={}", dest.display());
}


