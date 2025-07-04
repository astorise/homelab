use std::process::Command;
use std::error::Error;
use std::str;
use std::string::String;

use crate::tools;


pub(crate) fn deploy_gitlab(instance_name: &str) -> Result<(), Box<dyn Error>> {
  let commands: Vec<String> = vec![
      r#"echo '
apiVersion: batch/v1
kind: Job
metadata:
  name: create-minio-buckets
  namespace: minio
spec:
  template:
    spec:
      containers:
      - name: create-buckets
        image: minio/mc
        command: ["/bin/sh", "-c", \"set -e;
          mc alias set myminio http://minio:9000 $MINIO_ACCESS_KEY $MINIO_SECRET_KEY;
          mc mb myminio/gitlab-artifacts;
          mc mb myminio/gitlab-lfs;
          mc mb myminio/gitlab-uploads;
          mc mb myminio/gitlab-packages;
          mc mb myminio/gitlab-mr-diffs;
          mc mb myminio/gitlab-external-diffs;
          mc mb myminio/gitlab-backup\"]
        env:
        - name: MINIO_ACCESS_KEY
          valueFrom:
            secretKeyRef:
              name: minio-env-configuration
              key: accessKey
        - name: MINIO_SECRET_KEY
          valueFrom:
            secretKeyRef:
              name: minio-env-configuration
              key: secretKey
      restartPolicy: OnFailure
'| kubectl apply -f -
      "#.to_string(),
    format!(r#"kubeconfig_devops=$(kubectl get secret devops-kubeconfig -n devops -o jsonpath='{{.data.kubeconfig}}' | base64 -d)   && kubectl --kubeconfig=<(echo "$kubeconfig_devops") create namespace gitlab   && kubectl --kubeconfig=<(echo "$kubeconfig_devops") create secret generic gitlab-postgresql-password --from-literal=postgresql-password={} --namespace gitlab      && kubectl --kubeconfig=<(echo "$kubeconfig_devops") create secret generic gitlab-redis-password --from-literal=redis-password={} --namespace gitlab 
    "#, tools::generate_password(32), tools::generate_password(32)) ,
 /*   r#"echo "
global:
minio:
  enabled: false
appConfig:
  artifacts:
    bucket: gitlab-artifacts
    connection:
      secret: minio
  lfs:
    bucket: gitlab-lfs
    connection:
      secret: minio
  uploads:
    bucket: gitlab-uploads
    connection:
      secret: minio
  packages:
    bucket: gitlab-packages
    connection:
      secret: minio
  externalDiffs:
    bucket: gitlab-external-diffs
    connection:
      secret: minio
  backup:
    bucket: gitlab-backup
    connection:
      secret: minio

minio:
enabled: false

gitlab:
gitaly:
  persistence:
    size: 200Gi

postgresql:
existingSecret: gitlab-postgresql-password
persistence:
  size: 200Gi

redis:
existingSecret: gitlab-redis-password
persistence:
  size: 200Gi
" | helm template gitlab gitlab --repo https://charts.gitlab.io/  --namespace gitlab | kubectl  apply -f - --kubeconfig=<(echo "$kubeconfig_devops")
"#.to_string() */ 
  ];

  for command in commands {
      let output = Command::new("wsl")
          .args(&["-d", instance_name, "--", "sh", "-c", &command])
          .output()
          .expect("Échec de l'exécution de la commande");
      if !output.status.success() {
          eprintln!(
              "La commande a échoué avec la sortie: {}",
              String::from_utf8_lossy(&output.stderr)
          );
      } else {
          println!(
              "Commande exécutée avec succès: {}",
              String::from_utf8_lossy(&output.stdout)
          );
      }
  }

  Ok(())
}

