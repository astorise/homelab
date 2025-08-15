# home-proxy-grpc-client

Client gRPC (Rust, tonic) pour le service **Home Proxy** sur **pipe nommé Windows** `\\.\pipe\home-proxy`.

## Utilisation

```toml
# Cargo.toml
[dependencies]
home-proxy-grpc-client = { path = "." }
anyhow = "1"
tokio = { version = "1", features = ["full"] }
```

```rust
use home_proxy_client::*;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut client = connect_default().await?;
    let status = client.get_status(homeproxy::Empty{}).await?.into_inner();
    println!("state={}, level={}", status.state, status.log_level);
    Ok(())
}
```

## Exemple CLI

```
cargo run --example cli
```

> Remarque : fonctionne uniquement sous **Windows** (tonic + tokio named pipes).
