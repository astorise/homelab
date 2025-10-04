use anyhow::{anyhow, Result};
use local_rpc::Client as RpcClient;
use prost::Message;
use windows_sys::core::GUID;

pub mod homedns {
    pub mod homedns {
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/homedns.v1.rs"));
        }
    }
}
pub mod homehttp {
    pub mod homehttp {
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/homehttp.v1.rs"));
        }
    }
}

const DNS_UUID: GUID = GUID::from_u128(0x18477de6c4b24746b60492db45db2d31);
const HTTP_UUID: GUID = GUID::from_u128(0x9df99e13af1c480cb5e64864350b5f3e);
const RPC_VERSION: (u16, u16) = (1, 0);

fn connect(endpoints: &[&str], uuid: GUID) -> Result<RpcClient> {
    let mut last_err = None;
    for ep in endpoints {
        match RpcClient::connect(uuid, RPC_VERSION, ep) {
            Ok(client) => return Ok(client),
            Err(err) => last_err = Some((*ep, err)),
        }
    }
    let (ep, err) = last_err.ok_or_else(|| anyhow!("no endpoints provided"))?;
    Err(anyhow!("connect {ep}: {err}"))
}

fn main() -> Result<()> {
    println!("Testing RPC endpoints...");

    // DNS
    {
        let client = connect(&["home-dns-dev", "home-dns"], DNS_UUID)?;
        let bytes = client.call(2, &homedns::homedns::v1::Empty {}.encode_to_vec())?;
        let status = homedns::homedns::v1::StatusResponse::decode(bytes.as_slice())?;
        println!("DNS status: {:?}", status);
    }

    // HTTP
    {
        let client = connect(&["home-http-dev", "home-http"], HTTP_UUID)?;
        let bytes = client.call(2, &homehttp::homehttp::v1::Empty {}.encode_to_vec())?;
        let status = homehttp::homehttp::v1::StatusResponse::decode(bytes.as_slice())?;
        println!("HTTP status: {:?}", status);
    }

    Ok(())
}
