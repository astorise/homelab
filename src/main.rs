
use std::error::Error;


mod alpine;
mod k3s;
mod helm;
mod vcluster;
mod minio;
mod tools;
mod gitlab;
mod prometheus;






//#[tokio::main]
fn main() -> std::result::Result<(), Box<dyn Error>> {
    let instance_k3_name = "k3s";
    println!("Installation Alpine");
    alpine::import_alpine(instance_k3_name).expect("Erreur installation Alpine K3S");
    println!("Installation K3S");    
    k3s::install_k3s(instance_k3_name).expect("Erreur installation K3S");
    println!("Installation Helm");
    helm::install_helm(instance_k3_name).expect("Erreur installation helm");
    //println!("Installation prometheus");
    //prometheus::deploy_prometheus(instance_k3_name).expect("Erreur installation vcluster");
    //println!("Installation vcluster");
    //vcluster::install_vcluster(instance_k3_name).expect("Erreur installation vcluster");
    //println!("Deploy vcluster");
    //vcluster::deploy_vclusters(instance_k3_name).expect("Erreur déploiement vcluster");
    //minio::deploy_minio(instance_k3_name).expect("Erreur installation minio");
    //gitlab::deploy_gitlab(instance_k3_name).expect("Erreur déploiement gitlab");
    //vcluster::export_kubeconfig_vcluster(instance_k3_name).expect("Erreur export kubeconfig");
    //service::update_minio(instance_name).expect("Erreur update");

    Ok(())
}
