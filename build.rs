use std::env;
use std::fs;
use std::path::Path;

fn main() {
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");
    let dest = Path::new(&out_dir).join("wsl-image.tar");
    if let Ok(image_path) = env::var("WSL_IMAGE_ARCHIVE") {
        fs::copy(&image_path, &dest).expect("failed to copy image archive");
    } else {
        // create an empty placeholder so compilation still succeeds
        fs::write(&dest, &[] as &[u8]).expect("failed to create placeholder image");
        println!("cargo:warning=WSL_IMAGE_ARCHIVE not provided; offline install won't work");
    }
    println!("cargo:rustc-env=WSL_IMAGE_PATH={}", dest.display());
}

