use std::process;

fn usage() -> &'static str {
    "Usage: home-lab-cert <install-root>"
}

fn main() {
    if let Err(err) = run() {
        eprintln!("{err:#}");
        process::exit(1);
    }
}

fn run() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let Some(command) = args.next() else {
        println!("{}", usage());
        return Ok(());
    };

    match command.as_str() {
        "install-root" => {
            let result = home_pki::ensure_root_ca_installed()?;
            println!(
                "Home Lab root CA ready: location={:?} detail={}",
                result.location, result.detail
            );
            Ok(())
        }
        "-h" | "--help" | "help" => {
            println!("{}", usage());
            Ok(())
        }
        _ => Err(anyhow::anyhow!(
            "Unknown command '{}'. {}",
            command,
            usage()
        )),
    }
}
