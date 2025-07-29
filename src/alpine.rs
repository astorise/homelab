use std::error::Error;
use std::{fs, io::Write, path::Path, path::PathBuf, process::Command};

pub fn import_alpine(instance_name: &str, base_dir: &Path) -> Result<(), Box<dyn Error>> {
    let download_folder: PathBuf = base_dir.join(instance_name);
    if !download_folder.exists() {
        fs::create_dir_all(&download_folder)?;
    }
    let tar_file = download_folder.join("wsl-image.tar");

    if tar_file.exists() {
        fs::remove_file(&tar_file)?;
    }

    let bytes = include_bytes!(env!("WSL_IMAGE_PATH"));
    let mut file_alpine = fs::File::create(&tar_file)?;
    file_alpine.write_all(bytes)?;

    println!("Extracting image to {}", tar_file.display());
    println!("Importing distro into {}", download_folder.display());

    // Exécutez les commandes WSL
    unregister(instance_name)?;

    let output = Command::new("wsl")
        .arg("--import")
        .arg(instance_name)
        .arg(download_folder.to_str().unwrap())
        .arg(tar_file.to_str().unwrap())
        .arg("--version")
        .arg("2")
        .output()
        .expect("Échec de l'exécution de la commande WSL --import");

    println!(
        "WSL import stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    println!(
        "WSL import stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    if !output.status.success() {
        println!(
            "La commande WSL --import s'est terminée avec le code {:?}",
            output.status.code()
        );
    }

    Ok(())
}

pub fn unregister(instance_name: &str) -> Result<(), Box<dyn Error>> {
    Command::new("wsl")
        .arg("--unregister")
        .arg(instance_name)
        .status()?;
    Ok(())
}
