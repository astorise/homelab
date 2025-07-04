use std::error::Error;
use std::process::Command;

fn has_nvidia_gpu() -> bool {
    Command::new("nvidia-smi")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

pub(crate) fn install_cuda(instance_name: &str) -> Result<(), Box<dyn Error>> {
    if !has_nvidia_gpu() {
        println!("No NVIDIA GPU detected. Skipping CUDA setup.");
        return Ok(());
    }

    let commands = vec![
        "apk update && apk add --no-cache cuda nvidia-container-toolkit".to_string(),
        "curl -sL https://raw.githubusercontent.com/NVIDIA/k8s-device-plugin/v0.14.1/nvidia-device-plugin.yml | kubectl apply -f -".to_string(),
    ];

    for cmd in commands {
        Command::new("wsl")
            .args(&["-d", instance_name, "--", "sh", "-c", &cmd])
            .status()?;
    }

    println!("CUDA support installed.");
    Ok(())
}
