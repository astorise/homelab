
use anyhow::Result;
use home_proxy_client::*;

#[tokio::main]
async fn main() -> Result<()> {
    let mut client = connect_default().await?;

    // Status
    let status = client.get_status(homeproxy::Empty{}).await?.into_inner();
    println!("state={}, log_level={}", status.state, status.log_level);

    // List routes
    let routes = client.list_routes(homeproxy::Empty{}).await?.into_inner();
    for r in routes.routes {
        println!("route: {} -> {}", r.host, r.port);
    }

    // Add a route (example)
    // let _ = client.add_route(homeproxy::AddRouteRequest{ host: "test.local".into(), port: 3000 }).await?;

    Ok(())
}
