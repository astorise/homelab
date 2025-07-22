use std::error::Error;
use std::{fs, io::Write, path::Path, process::Command};

pub fn import_alpine(instance_name: &str) -> Result<(), Box<dyn Error>> {
    let folder = format!("C:\\wsldistros\\{}", instance_name);
    let download_folder = Path::new(&folder);
    if !download_folder.exists() {
        fs::create_dir_all(download_folder)?;
    }
    let tar_file = download_folder.join("wsl-image.tar");

    if !tar_file.exists() {
        let bytes = include_bytes!(env!("WSL_IMAGE_PATH"));
        let mut file_alpine = fs::File::create(&tar_file)?;
        file_alpine.write_all(bytes)?;
    }

    // Exécutez les commandes WSL
    unregister(instance_name)?;

    Command::new("wsl")
        .arg("--import")
        .arg(instance_name)
        .arg(download_folder.to_str().unwrap())
        .arg(tar_file.to_str().unwrap())
        .arg("--version")
        .arg("2")
        .output()
        .expect("Échec de l'exécution de la commande WSL --import");

    Ok(())
}

pub fn unregister(instance_name: &str) -> Result<(), Box<dyn Error>> {
    Command::new("wsl")
        .arg("--unregister")
        .arg(instance_name)
        .status()?;
    Ok(())
}
