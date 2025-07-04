use std::{io, process::Command};
use std::error::Error;




pub(crate) fn deploy_prometheus(instance_name: &str)->std::result::Result<(), Box<dyn Error>>  {
  println!(" {:?}", "deploy_prometheus");
  let commands: Vec<String> = vec![
    "kubectl create namespace prometheus".to_string(),
r#"export KUBECONFIG=/etc/rancher/k3s/k3s.yaml && echo "
# values.yaml
nodeExporter:
  enabled: false
prometheus-node-exporter:
  enabled: false
kubelet:
  enabled: true
  serviceMonitor:
    https: true
kubeStateMetrics:
  enabled: true
prometheus:
  prometheusSpec:
    ruleSelectorNilUsesHelmValues: false
    serviceMonitorSelectorNilUsesHelmValues: false
    podMonitorSelectorNilUsesHelmValues: false
    additionalScrapeConfigs:
      - job_name: 'kubelet'
        scheme: https
        tls_config:
          ca_file: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
          insecure_skip_verify: true
        bearer_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token
        kubernetes_sd_configs:
          - role: node
        relabel_configs:
          - action: labelmap
            regex: __meta_kubernetes_node_label_(.+)
          - target_label: __address__
            replacement: kubernetes.default.svc:443
          - source_labels: [__meta_kubernetes_node_name]
            regex: (.+)
            target_label: __metrics_path__
            replacement: /api/v1/nodes/\${1}/proxy/metrics
      - job_name: 'kubelet/cadvisor'
        scheme: https
        tls_config:
          ca_file: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
          insecure_skip_verify: true
        bearer_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token
        kubernetes_sd_configs:
          - role: node
        relabel_configs:
          - action: labelmap
            regex: __meta_kubernetes_node_label_(.+)
          - target_label: __address__
            replacement: kubernetes.default.svc:443
          - source_labels: [__meta_kubernetes_node_name]
            regex: (.+)
            target_label: __metrics_path__
            replacement: /api/v1/nodes/\${1}/proxy/metrics/cadvisor
    retention: 15d
    resources:
      requests:
        cpu: 100m
        memory: 100Mi
      limits:
        cpu: 500m
        memory: 500Mi
grafana:
  enabled: false
alertmanager:
  enabled: true
  alertmanagerSpec:
    retention: 120h
    resources:
      requests:
        cpu: 25m
        memory: 25Mi
      limits:
        cpu: 100m
        memory: 100Mi
prometheusOperator:
  resources:
    requests:
      cpu: 50m
      memory: 50Mi
    limits:
      cpu: 200m
      memory: 200Mi
   " | helm install prometheus kube-prometheus-stack --repo https://prometheus-community.github.io/helm-charts --namespace prometheus --create-namespace -f -"#.to_string(),
  ];

  for command in commands {
    
    let output =  Command::new("wsl")
        .args(&["-d", instance_name, "--", "sh", "-c", &command])
        .output()
    .expect("Échec de l'exécution de la commande");
  let stdout = String::from_utf8_lossy(&output.stdout);
  let stderr = String::from_utf8_lossy(&output.stderr);
  
  if !stderr.is_empty() {
    println!("command:{}, log:{}, err:{}", command, stdout, stderr);
    println!("Appuyez sur Entrée pour continuer...");
    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("Erreur lors de la lecture de l'entrée utilisateur");
}
    }

   
    Ok(())
  }