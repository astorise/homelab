use reqwest::blocking::Client;
use serde_yaml::Value;
use std::{fs, path::Path, process::Command};
use std::error::Error;
use std::io::Write;

pub fn import_alpine(instance_name: &str) -> Result<(), Box<dyn Error>> {
    let yaml_url = "https://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/x86_64/latest-releases.yaml";

    // Téléchargez le fichier YAML de manière synchrone
    let client = Client::new();
    let yaml_content = client.get(yaml_url).send()?.text()?;

    // Parsez le YAML
    let docs: Vec<Value> = serde_yaml::from_str(&yaml_content)?;
    let mut file_name = String::new();
    for doc in docs {
        if let Some(flavor) = doc["flavor"].as_str() {
            if flavor == "alpine-minirootfs" {
                if let Some(file) = doc["file"].as_str() {
                    file_name = file.to_string();
                    break;
                }
            }
        }
    }

    if file_name.is_empty() {
        return Err("Alpine minirootfs file not found".into());
    }
println!("Alpine: {}",file_name);
 let alpine_url = format!("https://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/x86_64/{}", file_name);
 
 //let alpine_url =  "https://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/x86_64/alpine-netboot-3.20.0-x86_64.tar.gz";
    let folder = format!("C:\\wsldistros\\{}", instance_name);
    let download_folder = Path::new(&folder);
    if !download_folder.exists() {
        fs::create_dir_all(download_folder)?;
    }
    let tar_gz_file = download_folder.join("alpine-minirootfs.tar.gz");

    if !tar_gz_file.exists() {
        let response = client.get(alpine_url).send()?;
        let mut file_alpine = fs::File::create(&tar_gz_file)?;
        file_alpine.write_all(&response.bytes()?)?;
    }

    // Exécutez les commandes WSL
    Command::new("wsl")
        .arg("--unregister")
        .arg(instance_name)
        .output()
        .expect("Échec de l'exécution de la commande WSL --unregister"); 

    Command::new("wsl")
        .arg("--import")
        .arg(instance_name)
        .arg(download_folder.to_str().unwrap())
        .arg(tar_gz_file.to_str().unwrap())
        .arg("--version 2")
        .output()
        .expect("Échec de l'exécution de la commande WSL --import");

    Ok(())
}
