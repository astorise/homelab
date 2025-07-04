use std::process::Command;
use std::error::Error;

use crate::tools;


pub(crate) fn deploy_minio(instance_name: &str)->std::result::Result<(), Box<dyn Error>>  {
  println!(" {:?}", "deploy_minio");
  let commands: Vec<String> = vec![
    "kubectl create namespace minio &&  helm template minio-operator operator --repo https://operator.min.io/ --namespace minio  --set crd.create=true|kubectl apply -f -".to_string(),
    r#"[ ! -d /mnt/c/minIO ] && mkdir -p /mnt/c/minIO "#.to_string(),
    r#"echo "
apiVersion: v1
kind: PersistentVolume
metadata:
  name: minio-pv
spec:
  capacity:
    storage: 100Gi  
  volumeMode: Filesystem
  accessModes:
    - ReadWriteOnce
  persistentVolumeReclaimPolicy: Retain  
  storageClassName: local-path
  local:
    path: /mnt/c/minIO
  nodeAffinity:
    required:
      nodeSelectorTerms:
        - matchExpressions:
          - key: kubernetes.io/hostname
            operator: In
            values:
              - "host"
     "| kubectl apply -f -"#.to_string(),
    r#"echo "
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: minio-pvc
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 100Gi
  volumeName: minio-pv
        "| kubectl apply --namespace minio -f -"#.to_string(),
        "kubectl -n minio wait --for=condition=ready pod -l app.kubernetes.io/name=operator --timeout=300s".to_string(),
        "kubectl wait --for=jsonpath='{.status.phase}'=Bound pvc/minio-pvc -n minio  --timeout=300s".to_string(),
  format!(r#"echo "
secrets:
  name: minio-env-configuration
  accessKey: {} 
  secretKey: {}
tenant:
  name: minio
  configuration:
    name: minio-env-configuration
  pools:
    - servers: 1
      name: pool-0
      volumesPerServer: 1
      volumeClaimTemplate:
        metadata:
          name: minio-pvc
        spec:
          accessModes: ["ReadWriteOnce"]
          resources:
            requests:
              storage: 100Gi
              "|helm template tenant tenant --repo https://operator.min.io/ --namespace minio -f - | kubectl apply --namespace minio -f -"#,tools::generate_password(16),tools::generate_password(16)),
              format!(r#"echo "
secrets:
  name: minio-env-configuration
  accessKey: {} 
  secretKey: {}
tenant:
  name: minio-tenant
  configuration:
    name: minio-env-configuration
  pools:
    - servers: 1
      volumesPerServer: 1
      volumeClaimTemplate:
        metadata:
          name: minio-pvc
        spec:
          accessModes: ["ReadWriteOnce"]
          resources:
            requests:
              storage: 100Gi
              "|helm template tenant tenant --repo https://operator.min.io/ --namespace minio -f - "#,tools::generate_password(16),tools::generate_password(16))
  ];

  for command in commands {
    
    let output =  Command::new("wsl")
        .args(&["-d", instance_name, "--", "sh", "-c", &command])
        .output()
    .expect("Échec de l'exécution de la commande");
  println!("log:{}, err:{}",String::from_utf8_lossy(&output.stdout),String::from_utf8_lossy(&output.stderr));
    }

   
    Ok(())
}

pub(crate) fn create_bucket(instance: &str, bucket: &str) -> std::result::Result<(), Box<dyn Error>> {
    Command::new("wsl")
        .args(&["-d", instance, "--", "sh", "-c", &format!("mc mb {}", bucket)])
        .status()?;
    Ok(())
}

pub(crate) fn delete_bucket(instance: &str, bucket: &str) -> std::result::Result<(), Box<dyn Error>> {
    Command::new("wsl")
        .args(&["-d", instance, "--", "sh", "-c", &format!("mc rb {}", bucket)])
        .status()?;
    Ok(())
}
