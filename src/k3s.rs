use std::{error::Error, process::Command, thread, time::Duration};

pub(crate) fn install_k3s(instance_name: &str) -> std::result::Result<(), Box<dyn Error>> {
    Command::new("wsl")
        .arg("-d")
        .arg(instance_name)
        .args(["sh", "-c", "apk update && apk upgrade"])
        .output()
        .expect("Échec de l'exécution de la commande");

    // Ensure the k3s binary from the base image is available under /usr/local/bin
    Command::new("wsl")
        .arg("-d")
        .arg(instance_name)
        .args([
            "sh",
            "-c",
            "[ -f /usr/local/bin/k3s ] || ln -s /bin/k3s /usr/local/bin/k3s",
        ])
        .status()?;

    // Copier le script dans WSL et le rendre exécutable, puis l'exécuter
    let commands = vec![
  r#"echo '
  IP_ETH0=\$(ip -4 a show dev eth0 | grep -oE "inet ([0-9]{1,3}\.){3}[0-9]{1,3}"| grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}")
  sed -i "/k3s\.wsl\|devops\.k3s\.wsl\|staging\.k3s\.wsl\|prod\.k3s\.wsl/d" /etc/hosts
  echo "
\$IP_ETH0 k3s.wsl
\$IP_ETH0 devops.k3s.wsl
\$IP_ETH0 staging.k3s.wsl
\$IP_ETH0 prod.k3s.wsl" >> /etc/hosts
  while ! nc -z -w 1 google.com 80 >/dev/null 2>&1; do
  sleep 5
  done
  nohup /usr/local/bin/k3s server --disable traefik --kube-apiserver-arg=bind-address=0.0.0.0 --server k3s.wsl --https-listen-port 6444 --service-node-port-range=1-65535 --cluster-domain k3s.wsl --node-external-ip=\$IP_ETH0 --tls-san k3s.wsl --write-kubeconfig-mode 600 > /var/log/k3s 2>&1 &
  sleep 5
  cp /etc/rancher/k3s/k3s.yaml ~/.kube/config
  export KUBECONFIG=/etc/rancher/k3s/k3s.yaml' > /etc/init.d/k3s"#.to_string(),
  "echo 'export KUBECONFIG=/etc/rancher/k3s/k3s.yaml'>> ~/.ashrc".to_string(),
  "echo '. ~/.ashrc' >> ~/.profile".to_string(),
  "chmod +x /etc/init.d/k3s".to_string(),
  ". /etc/init.d/k3s".to_string(),
  r#"printf '
  [network]
  generateHosts = false
  generateResolvConf = true
  # Add/Edit the [boot] command and save the file
  [boot]
  command = "sh /etc/init.d/k3s"' > /etc/wsl.conf"#.to_string(),
  "echo 'exec k3s kubectl $''@' > /usr/local/bin/kubectl".to_string(),
  "chmod +x /usr/local/bin/kubectl".to_string()
  ];

    for command in commands {
        Command::new("wsl")
            .args(&["-d", instance_name, "--", "sh", "-c", &command])
            .status()?;
    }
    Command::new("wsl")
        .args(&["--terminate", instance_name])
        .status()?;
    wait_k3s(instance_name);
    Ok(())
}

fn wait_k3s(instance_name: &str) {
    let mut nodes_ready = false;
    while !nodes_ready {
        // Exécuter la commande dans WSL
        let output = Command::new("wsl")
      .args(&["-d", instance_name, "--", "sh", "-c","kubectl get nodes -o jsonpath='{.items[*].status.conditions[?(@.type==\"Ready\")].status}'"])
          .output()
          .expect("failed to execute process");

        let status = String::from_utf8_lossy(&output.stdout);
        if status.contains("True") {
            println!("Tous les nœuds sont prêts !");
            nodes_ready = true;
        } else {
            println!(
                "Les nœuds ne sont pas encore prêts. Statut: {}",
                status.trim()
            );
        }

        if !nodes_ready {
            // Attendre quelques secondes avant de réessayer
            thread::sleep(Duration::from_secs(5));
        }
    }
}

pub(crate) fn uninstall_k3s(instance_name: &str) -> Result<(), Box<dyn Error>> {
    Command::new("wsl")
        .args(&["-d", instance_name, "--", "sh", "-c", "k3s-uninstall.sh"])
        .status()?;
    Ok(())
}

pub(crate) fn delete_namespace(instance_name: &str, namespace: &str) -> Result<(), Box<dyn Error>> {
    Command::new("wsl")
        .args(&[
            "-d",
            instance_name,
            "--",
            "sh",
            "-c",
            &format!("kubectl delete namespace {}", namespace),
        ])
        .status()?;
    Ok(())
}
