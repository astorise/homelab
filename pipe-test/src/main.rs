use anyhow::Result;
use tokio::net::windows::named_pipe::ClientOptions;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

pub mod homedns {
    pub mod homedns {
        pub mod v1 {
            tonic::include_proto!("homedns.v1");
        }
    }
}
pub mod homehttp {
    pub mod homehttp {
        pub mod v1 {
            tonic::include_proto!("homehttp.v1");
        }
    }
}

async fn connect_pipe(path: &str) -> Result<Channel> {
    let ep = Endpoint::try_from("http://pipe.invalid")?
        .connect_timeout(std::time::Duration::from_secs(3));
    let p = path.to_string();
    let ch = ep
        .connect_with_connector(service_fn(move |_uri: Uri| {
            let p2 = p.clone();
            async move {
                let client = ClientOptions::new().open(&p2)?;
                Ok::<_, std::io::Error>(client)
            }
        }))
        .await?;
    Ok(ch)
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("Testing pipes...");
    // DNS
    {
        let ch = connect_pipe(r"\\.\pipe\home-dns").await?;
        let mut cli = homedns::homedns::v1::home_dns_client::HomeDnsClient::new(ch);
        let resp = cli.get_status(homedns::homedns::v1::Empty {}).await?;
        println!("DNS: {:?}", resp.into_inner());
    }
    // HTTP
    {
        let ch = connect_pipe(r"\\.\pipe\home-http").await?;
        let mut cli = homehttp::homehttp::v1::home_http_client::HomeHttpClient::new(ch);
        let resp = cli.get_status(homehttp::homehttp::v1::Empty {}).await?;
        println!("HTTP: {:?}", resp.into_inner());
    }
    Ok(())
}
