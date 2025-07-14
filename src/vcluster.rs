use std::{io, process::Command};
use std::error::Error;
use std::str;
use serde::{Deserialize, Serialize};
use serde_yaml;

#[derive(Serialize, Deserialize, Debug)]
struct ClusterConfig {
    apiVersion: String,
    clusters: Vec<Cluster>,
    contexts: Vec<Context>,
    current_context: String,
    kind: String,
    preferences: Preferences,
    users: Vec<User>,
}

#[derive(Serialize, Deserialize, Debug)]
struct Cluster {
    name: String,
    cluster: ClusterDetails,
}

#[derive(Serialize, Deserialize, Debug)]
struct ClusterDetails {
    #[serde(rename = "certificate-authority-data")]
    certificate_authority_data: String,
    server: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct Context {
    name: String,
    context: ContextDetails,
}

#[derive(Serialize, Deserialize, Debug)]
struct ContextDetails {
    cluster: String,
    user: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct Preferences {}

#[derive(Serialize, Deserialize, Debug)]
struct User {
    name: String,
    user: UserDetails,
}

#[derive(Serialize, Deserialize, Debug)]
struct UserDetails {
    token: String,
}

pub(crate) fn install_vcluster(instance_name: &str)->std::result::Result<(), Box<dyn Error>>  {
    Command::new("wsl")
    .arg("-d")
    .arg(instance_name)
    .args([
        "sh",
        "-c",
        format!(
    //        " wget -O /usr/local/bin/vcluster https://github.com/loft-sh/vcluster/releases/latest/download/vcluster-linux-amd64  && chmod +x /usr/local/bin/vcluster"
    " wget -O /usr/local/bin/vcluster https://github.com/loft-sh/vcluster/releases/download/v0.20.0-beta.12/vcluster-linux-amd64  && chmod +x /usr/local/bin/vcluster"
     )
        .as_str(),
    ])
    .output()
    .expect("Échec de l'exécution de la commande");
  
    Ok(())
  }

  pub(crate) fn deploy_vclusters(instance_name: &str)->std::result::Result<(), Box<dyn Error>>  {
    let vclusters = vec![
      "devops",
      "staging",
      "prod"
  ];
  
  deploy_ingress(instance_name);
  for vcluster_name in vclusters {
   deploy_vcluster(instance_name,vcluster_name)?;
  }
  
  deploy_cert_manager(instance_name);
  let vclusters = vec![
    "devops",
    "staging",
    "prod"];
    // Générer les kubeconfigs pour chaque vcluster
    for vcluster_name in vclusters {
     generate_kubeconfig(instance_name,vcluster_name)?;
  }
   
      Ok(())
    }
   

  fn deploy_vcluster(instance_name: &str,vcluster_name: &str)-> Result<(), Box<dyn std::error::Error>>{
println!("Delpoy cluser:{}",vcluster_name);
    let commands = vec![

format!("kubectl create namespace {}",vcluster_name),
  format!(r###"export KUBECONFIG=/etc/rancher/k3s/k3s.yaml && echo "
# Configure vCluster's control plane components and deploymet.
controlPlane:
  # Distro holds virtual cluster related distro options. A distro cannot be changed after vCluster is deployed.
  distro:
    # K3S holds K3s relevant configuration.
    k3s:
      # Enabled specifies if the K3s distro should be enabled. Only one distro can be enabled at the same time.
      enabled: true
      # Command is the command to start the distro binary. This will override the existing command.
      command: []
      # ExtraArgs are additional arguments to pass to the distro binary.
      extraArgs: []
      # ImagePullPolicy is the pull policy for the distro image
      imagePullPolicy: ''
      # Image is the distro image
      image:
        # Registry is the registry of the container image, e.g. my-registry.com or ghcr.io. This setting can be globally
        # overridden via the controlPlane.advanced.defaultImageRegistry option. Empty means docker hub.
        registry: ''
        # Repository is the repository of the container image, e.g. my-repo/my-image
        repository: 'rancher/k3s'
        # Tag is the tag of the container image, e.g. latest
        tag: 'v1.30.2-k3s1'
      # Security options can be used for the distro init container
      securityContext: {{}}
      # Resources for the distro init container
      resources:
        limits:
          cpu: 100m
          memory: 256Mi
        requests:
          cpu: 40m
          memory: 64Mi
  # Proxy defines options for the virtual cluster control plane proxy that is used to do authentication and intercept requests.
  proxy:
    # BindAddress under which vCluster will expose the proxy.
    bindAddress: '0.0.0.0'
    # Port under which vCluster will expose the proxy. Changing port is currently not supported.
    port: 8443
    # ExtraSANs are extra hostnames to sign the vCluster proxy certificate for.
    extraSANs: [{}.k3s.wsl]
# StatefulSet defines options for vCluster statefulSet deployed by Helm.
  statefulSet:
    labels: {{}}
    annotations: {{}}
    # ImagePullPolicy is the policy how to pull the image.
    imagePullPolicy: ''
    # Image is the image for the controlPlane statefulSet container
    image:
      # Configure the registry of the container image, e.g. my-registry.com or ghcr.io
      # It defaults to ghcr.io and can be overriding either by using this field or controlPlane.advanced.defaultImageRegistry
      registry: 'ghcr.io'
      # Configure the repository of the container image, e.g. my-repo/my-image.
      # It defaults to the vCluster pro repository that includes the optional pro modules that are turned off by default.
      # If you still want to use the pure OSS build, use 'loft-sh/vcluster-oss' instead.
      repository: 'loft-sh/vcluster-oss'
      # Tag is the tag of the container image, e.g. latest
      tag: ''
    # WorkingDir specifies in what folder the main process should get started.
    workingDir: ''
    # Command allows you to override the main command.
    command: []
    # Args allows you to override the main arguments.
    args: []
    # Env are additional environment variables for the statefulSet container.
    env: []
    # Resources are the resource requests and limits for the statefulSet container.
    resources:
      # Limits are resource limits for the container
      limits:
        ephemeral-storage: 8Gi
        memory: 2Gi
      # Requests are minimal resources that will be consumed by the container
      requests:
        ephemeral-storage: 400Mi
        cpu: 200m
        memory: 256Mi
    # Additional labels or annotations for the statefulSet pods.
    pods:
      labels: {{}}
      annotations: {{}}
    # HighAvailability holds options related to high availability.
    highAvailability:
      # Replicas is the amount of replicas to use for the statefulSet.
      replicas: 1
      # LeaseDuration is the time to lease for the leader.
      leaseDuration: 60
      # RenewDeadline is the deadline to renew a lease for the leader.
      renewDeadline: 40
      # RetryPeriod is the time until a replica will retry to get a lease.
      retryPeriod: 15
    # Security defines pod or container security context.
 
# Networking options related to the virtual cluster.
networking:
  # ReplicateServices allows replicating services from the host within the virtual cluster or the other way around.
  replicateServices:
    # ToHost defines the services that should get synced from virtual cluster to the host cluster. If services are
    # synced to a different namespace than the virtual cluster is in, additional permissions for the other namespace
    # are required.
    toHost: []
    # FromHost defines the services that should get synced from the host to the virtual cluster.
    fromHost: []
  
  # ResolveDNS allows to define extra DNS rules. This only works if embedded coredns is configured.
  resolveDNS: []
  
  # Advanced holds advanced network options.
  advanced:
    # ClusterDomain is the Kubernetes cluster domain to use within the virtual cluster.
    clusterDomain: 'cluster.local'
    # FallbackHostCluster allows to fallback dns to the host cluster. This is useful if you want to reach host services without
    # any other modification. You will need to provide a namespace for the service, e.g. my-other-service.my-other-namespace
    fallbackHostCluster: false
    # ProxyKubelets allows rewriting certain metrics and stats from the Kubelet to 'fake' this for applications such as
    # prometheus or other node exporters.
    proxyKubelets:
      # ByHostname will add a special vCluster hostname to the nodes where the node can be reached at. This doesn't work
      # for all applications, e.g. Prometheus requires a node IP.
      byHostname: true
      # ByIP will create a separate service in the host cluster for every node that will point to virtual cluster and will be used to
      # route traffic.
      byIP: true

# Policies to enforce for the virtual cluster deployment as well as within the virtual cluster.
policies:
  # ResourceQuota specifies resource quota options.
  resourceQuota:
    # Enabled defines if the resource quota should be enabled.
    enabled: false
    labels: {{}}
    annotations: {{}}
    # Quota are the quota options
    quota:
      requests.cpu: 2
      requests.memory: 2Gi
      requests.storage: '10Gi'
      requests.ephemeral-storage: 6Gi
      limits.cpu: 4
      limits.memory: 4Gi
      limits.ephemeral-storage: 16Gi
      services.nodeports: 0
      services.loadbalancers: 1
      count/endpoints: 40
      count/pods: 20
      count/services: 20
      count/secrets: 100
      count/configmaps: 100
      count/persistentvolumeclaims: 20
    # ScopeSelector is the resource quota scope selector
    scopeSelector:
      matchExpressions: []
    # Scopes are the resource quota scopes
    scopes: []
  
  # LimitRange specifies limit range options.
  limitRange:
    # Enabled defines if the limit range should be deployed by vCluster.
    enabled: false
    labels: {{}}
    annotations: {{}}
    # Default are the default limits for the limit range
    default:
      ephemeral-storage: 2Gi
      memory: 256Mi
      cpu: '1'
    # DefaultRequest are the default request options for the limit range
    defaultRequest:
      ephemeral-storage: 1Gi
      memory: 128Mi
      cpu: 100m
  
# ExportKubeConfig describes how vCluster should export the vCluster kubeConfig file.
exportKubeConfig:
  # Context is the name of the context within the generated kubeconfig to use.
  context: '{}'
  
  # Override the default https://localhost:8443 and specify a custom hostname for the generated kubeconfig.
  server: 'https://{}.k3s.wsl:8443'
  
# External holds configuration for tools that are external to the vCluster.
external: {{}}

# Define which vCluster plugins to load.
plugins: {{}}

     "|helm install {} vcluster --repo https://charts.loft.sh --version v0.20.0-beta.12 -n {} -f -"###,vcluster_name,vcluster_name,vcluster_name,vcluster_name,vcluster_name),
     format!(r###"kubectl wait --for=condition=ready pod/{}-0 -n {} --timeout=300s && echo '
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: {}-vcluster-ingress
  namespace: {}
  annotations:
    haproxy.org/logging: "true"
    haproxy.org/log-format: 'timestamp=%Ts.%ms\ client=%ci\ method=%HM\ path=%HP\ status=%ST\ bytes=%B\ duration=%Tt'
    ingress.kubernetes.io/ssl-passthrough: "true"
    haproxy.org/ssl-passport: "6443"
    haproxy.org/backend-check-path: "/healthz"
    haproxy.org/backend-check-interval: "10s"
    haproxy.org/backend-check-type: "https"  
    haproxy.org/backend-check-ssl-verify: "none" 
    
spec:
  ingressClassName: haproxy
  rules:
  - host: {}.k3s.wsl
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: {}
            port:
              number: 10250
'| kubectl apply -f -"###,vcluster_name,vcluster_name,vcluster_name,vcluster_name,vcluster_name,vcluster_name),
      ];

     for command in commands {
    //  println!("commande:{}",command);
    let  output =Command::new("wsl")
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
  

pub(crate) fn generate_kubeconfig(instance_name: &str,vcluster_name: &str) -> Result<(), Box<dyn std::error::Error>> {
  let output = Command::new("wsl")
.args(&["-d",
    instance_name,
    "--",
    "sh",
    "-c",
    format!(r###"kubectl wait --for=condition=ready pod/{}-0 -n {} --timeout=300s && kubectl exec -i {}-0 -n {} -- cat /data/k3s-config/kube-config.yaml | sed "s|https://127.0.0.1:6443|https://{}.k3s.wsl:6443|" | base64 -w 0 | xargs -I {{}} sh -c 'echo -e "apiVersion: v1\nkind: Secret\nmetadata:\n  name: {}-kubeconfig\n  namespace: {}\ndata:\n  kubeconfig: {{}}" | kubectl apply -f -'"###,vcluster_name,vcluster_name,vcluster_name,vcluster_name,vcluster_name,vcluster_name,vcluster_name).as_str()])
    .output()
        .expect("Échec de l'exécution de la commande")
        ;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        
        if !stderr.is_empty() {
          println!("command:{}, log:{}, err:{}", format!(r###"kubectl wait --for=condition=ready pod/{}-0 -n {} --timeout=300s && kubectl exec -i {}-0 -n {} -- cat /data/k3s-config/kube-config.yaml | sed "s|https://127.0.0.1:6443|https://{}.k3s.wsl:6443|" | base64 -w 0 | xargs -I {{}} sh -c 'echo -e "apiVersion: v1\nkind: Secret\nmetadata:\n  name: {}-kubeconfig\n  namespace: {}\ndata:\n  kubeconfig: {{}}" | kubectl apply -f -'"###,vcluster_name,vcluster_name,vcluster_name,vcluster_name,vcluster_name,vcluster_name,vcluster_name), stdout, stderr);
      }
    Ok(())
}

  fn get_k8s_secret(instance_name: &str, vcluster_name: &str, secret_key: &str) -> String {
    let output = Command::new("wsl")
        .args(&["-d", instance_name, "--", "sh", "-c",
                format!("kubectl get secret vc-{} -n {} -o jsonpath='{{.data.{}}}'", vcluster_name, vcluster_name, secret_key).as_str()])
        .output()
        .expect("Échec de l'exécution de la commande")
        .stdout;

    str::from_utf8(&output).expect("Échec de la conversion de la sortie").trim().to_string()
}

fn deploy_ingress(instance_name: &str){
  let commands = vec![
    "kubectl create namespace ingress".to_string(),
    r###"echo '
apiVersion: v1
kind: ConfigMap
metadata:
  name: sni-map-config
  namespace: ingress
data:
  sni_6443.map: |
    k3s.wsl                 default_kubernetes_https
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: haproxy-auxiliary-configmap
  namespace: ingress
data:
  haproxy-auxiliary.cfg: |
    frontend ssl_6443
      mode tcp
      bind 0.0.0.0:6443 name v4
      bind [::]:6443 name v6 v4v6
      log stdout format raw local0
      log-format "%ci:%cp [%t] %ft %b/%s %Tw/%Tc/%Tt %B %ts %ac/%fc/%bc/%sc/%rc %sq/%bq %hr %hs SNI: %[var(sess.sni)] Backend: %[var(txn.sni_match),field(1,.)]"
      tcp-request content reject if !{ req_ssl_hello_type 1 }
      tcp-request inspect-delay 5000
      tcp-request content set-var(sess.sni) req_ssl_sni
      tcp-request content set-var(txn.sni_match) req_ssl_sni,map(/etc/haproxy/maps/sni_6443.map)
      tcp-request content set-var(txn.sni_match) req_ssl_sni,regsub(^[^.]*,,),map(/etc/haproxy/maps/sni_6443.map)
      option tcplog
      use_backend %[var(txn.sni_match),field(1,.)]
    ' | kubectl apply -f - "###.to_string(),
 r###"export KUBECONFIG=/etc/rancher/k3s/k3s.yaml && echo '
controller:
  kind: Deployment
  replicaCount: 1
  image:
    repository: haproxytech/kubernetes-ingress
    tag: "3.0.1"
  service:
    type: LoadBalancer
    tcpPorts:
      - name: k3s
        port: 6443
        targetPort: 6443
  initContainers:
    - name: debug-init
      image: busybox
      command: 
      - sh
      - -c
      - |
        echo "Debug init starting at $(date)"
        mkdir -p /etc/haproxy/maps
        ls -la /etc/haproxy/maps
        echo "Creating necessary files"
        touch /etc/haproxy/maps/host.map
        touch /etc/haproxy/maps/path-exact.map
        echo "k3s.wsl                 default_kubernetes_https"> /etc/haproxy/maps/path-prefix.map
        touch /etc/haproxy/maps/sni.map
        echo "Current contents:"
        ls -la /etc/haproxy/maps
        echo "Setting permissions for debug logs"
        echo "Debug init finished"
        sleep 30
      volumeMounts:
        - name: haproxy-maps
          mountPath: /etc/haproxy/maps
  extraVolumes:
    - name: haproxy-maps
      emptyDir: {}
    - name: haproxy-auxiliary-volume
      configMap:
        name: haproxy-auxiliary-configmap
    - name: sni-map
      configMap:
        name: sni-map-config
    - name: haproxy-config
      emptyDir: {}
  extraVolumeMounts:
    - name: haproxy-maps
      mountPath: /etc/haproxy/maps
    - name: haproxy-auxiliary-volume
      mountPath: /usr/local/etc/haproxy/haproxy-aux.cfg
      subPath: haproxy-auxiliary.cfg
    - name: sni-map
      mountPath: /etc/haproxy/maps/sni_6443.map
      subPath: sni_6443.map
      readOnly: true
  tolerations:
    - key: "node-role.kubernetes.io/master"
      operator: "Exists"
      effect: "NoSchedule"
    - key: "node-role.kubernetes.io/control-plane"
      operator: "Exists"
      effect: "NoSchedule"
  nodeSelector: {}
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 0
      maxSurge: 1
  securityContext:
    runAsUser: 0
    runAsGroup: 0
    allowPrivilegeEscalation: true
    capabilities:
      drop:
      - ALL
      add:
      - NET_BIND_SERVICE
  config:
    ssl-passthrough: "true"
    ssl-passthrough-port: "6443"
    backend-check-interval: 10s
    backend-check-https-path: /healthz
    backend-check-https-verify: none
    logging: log stdout format raw local0 debug
  extraArgs:
    - --v=9
    - --log-level=trace
    - --healthz-bind-port=1042
    - --log-ingress-changes
    - --enable-ssl-passthrough
    - --maps-dir=/etc/haproxy/maps
  startupProbe:
    failureThreshold: 60
    periodSeconds: 10
    timeoutSeconds: 5
    httpGet:
      path: /healthz
      port: 1042
  livenessProbe:
    failureThreshold: 3
    initialDelaySeconds: 10
    periodSeconds: 10
    successThreshold: 1
    timeoutSeconds: 1
    httpGet:
      path: /healthz
      port: 1042
      scheme: HTTP
  readinessProbe:
    failureThreshold: 3
    initialDelaySeconds: 10
    periodSeconds: 10
    successThreshold: 1
    timeoutSeconds: 1
    httpGet:
      path: /healthz
      port: 1042
      scheme: HTTP
  resources:
    limits:
      cpu: 100m
      memory: 200Mi
    requests:
      cpu: 50m
      memory: 100Mi
  ingressClass: haproxy
  defaultBackend:
    enabled: false
  metrics:
    enabled: true
  serviceMonitor:
    enabled: true
    labels:
      release: prometheus
' | helm install haproxy-ingress kubernetes-ingress --repo https://haproxytech.github.io/helm-charts -n ingress  -f - "###.to_string(),
"sleep 5".to_string(),
"kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=kubernetes-ingress -n ingress --timeout=60s".to_string(),
"kubectl get pods -n ingress".to_string(),
r###"echo '
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: hote-k3s-ingress
  namespace: default
  annotations:
    haproxy.org/logging: "true"
    haproxy.org/log-format: 'timestamp=%Ts.%ms\ client=%ci\ method=%HM\ path=%HP\ status=%ST\ bytes=%B\ duration=%Tt'
    ingress.kubernetes.io/ssl-passthrough: "true"
    haproxy.org/ssl-passport: "6443"
    haproxy.org/backend-check-path: "/healthz"
    haproxy.org/backend-check-interval: "10s"
    haproxy.org/backend-check-type: "https"  
    haproxy.org/backend-check-ssl-verify: "none" 
    
spec:
  ingressClassName: haproxy
  rules:
  - host: k3s.wsl
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: kubernetes
            port:
              number: 443
'| kubectl apply -f -"###.to_string()   
    ];
    
    for command in commands {
     // println!("commande:{}",command);
    let  output =Command::new("wsl")
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

}

fn deploy_cert_manager(instance_name: &str){


let  output =Command::new("wsl")
.args(&["-d", instance_name, "--", "sh", "-c", "export KUBECONFIG=/etc/rancher/k3s/k3s.yaml && kubectl create namespace cert-manager && helm install cert-manager cert-manager --repo https://charts.jetstack.io --namespace cert-manager --create-namespace --version v1.15.1 --set crds.enabled=true"])
.output()
.expect("Échec de l'exécution de la commande");
let stdout = String::from_utf8_lossy(&output.stdout);
let stderr = String::from_utf8_lossy(&output.stderr);

if !stderr.is_empty() {
  println!("command:{}, log:{}, err:{}", "helm install  cert-manager jetstack/cert-manager ", stdout, stderr);
  println!("Appuyez sur Entrée pour continuer...");
  let mut input = String::new();
  io::stdin().read_line(&mut input).expect("Erreur lors de la lecture de l'entrée utilisateur");
}
}


fn deploy_cert_manager_(instance_name: &str){
  let commands = vec![
    "kubectl create namespace cert-manager".to_string(),
    "kubectl apply  -f https://github.com/jetstack/cert-manager/releases/download/v1.15.1/cert-manager.crds.yaml".to_string(),
    "kubectl apply  -f https://github.com/jetstack/cert-manager/releases/download/v1.15.1/cert-manager.yaml".to_string()
    
    ];
    
    for command in commands {
     // println!("commande:{}",command);
    let  output =Command::new("wsl")
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
}

fn create_certificate(instance_name: &str,vcluster_name: &str){
  let commands = vec![
    format!(r###"kubectl wait --for=condition=ready pod/{}-0 -n {} --timeout=300s && echo "
    apiVersion: cert-manager.io/v1
    kind: Certificate
    metadata:
      name: {}-vcluster-cert
      namespace: {}
    spec:
      secretName: {}-vcluster-tls
      issuerRef:
        name: selfsigning-issuer
        kind: ClusterIssuer
      dnsNames:
      - '{}.k3s.wsl'
   
         "| kubectl apply -f -"###,vcluster_name,vcluster_name,vcluster_name,vcluster_name,vcluster_name,vcluster_name),
          ];
         for command in commands {
        //  println!("commande:{}",command);
        let  output =Command::new("wsl")
          .args(&["-d", instance_name, "--", "sh", "-c", &command])
          .output()
          .expect("Échec de l'exécution de la commande");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        
        if !stderr.is_empty() {
          println!("command:{}, log:{}, err:{}", command, stdout, stderr);
        }
        }
}