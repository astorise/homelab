use std::{error::Error, io::Read, path::Path};

use oci_distribution::client::{Client, ClientConfig};
use oci_distribution::secrets::RegistryAuth;
use oci_distribution::Reference;
use tokio::runtime::Runtime;

pub fn fetch_k3s_binary() -> Result<Vec<u8>, Box<dyn Error>> {
    let reference: Reference = "docker.io/rancher/k3s:latest".parse()?;
    let mut client = Client::new(ClientConfig::default());
    let auth = RegistryAuth::Anonymous;
    let rt = Runtime::new()?;
    let image = rt.block_on(client.pull(&reference, &auth, vec![]))?;

    for layer in image.layers {
        let mut decoder = flate2::read::GzDecoder::new(&layer.data[..]);
        let mut archive = tar::Archive::new(&mut decoder);
        for entry in archive.entries()? {
            let mut entry = entry?;
            if entry.path()? == Path::new("bin/k3s") {
                let mut buf = Vec::new();
                entry.read_to_end(&mut buf)?;
                return Ok(buf);
            }
        }
    }
    Err("k3s binary not found in image".into())
}
