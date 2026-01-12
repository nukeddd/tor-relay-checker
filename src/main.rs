use anyhow::Result;
use clap::Parser;
use futures::{stream, StreamExt};
use rand::seq::SliceRandom;
use reqwest::Client;
use serde::Deserialize;
use std::fs;
use std::io::{self, Write};
use std::path::{PathBuf};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

const DESCRIPTION: &str = "Downloads all Tor Relay IP addresses from onionoo.torproject.org and checks whether random Relays are available.";

#[derive(Parser, Debug)]
#[command(author, version, about = DESCRIPTION, long_about = None)]
struct Args {
    #[arg(short = 'n', long, default_value_t = 30)]
    num_relays: usize,
    #[arg(short = 'g', long, default_value_t = 10)]
    working_relay_num_goal: usize,
    #[arg(long, default_value_t = 10.0)]
    timeout: f64,
    #[arg(short = 'o', long = "outfile")]
    outfile: Option<PathBuf>,
    #[arg(long)]
    torrc_fmt: bool,
    #[arg(long)]
    proxy: Option<String>,
    #[arg(long)]
    url: Vec<String>,
    #[arg(short = 'p', long)]
    port: Vec<u16>,
}

#[derive(Deserialize, Debug, Clone)]
struct Relay {
    fingerprint: String,
    or_addresses: Vec<String>,
}

#[derive(Deserialize, Debug)]
struct OnionooResponse {
    relays: Vec<Relay>,
}

fn format_address(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", host, port)
    }
}

fn parse_or_addresses(or_addresses: &[String]) -> Vec<(String, u16)> {
    or_addresses
        .iter()
        .filter_map(|addr_str| {
            let (host_part, port_str) = addr_str.rsplit_once(':')?;
            let port = port_str.parse::<u16>().ok()?;
            let host = host_part
                .strip_prefix('[')
                .and_then(|h| h.strip_suffix(']'))
                .unwrap_or(host_part);
            Some((host.to_string(), port))
        })
        .collect()
}

async fn check_connection(host: &str, port: u16, timeout_duration: Duration) -> io::Result<()> {
    let address = format_address(host, port);
    let addrs = tokio::net::lookup_host(address).await?;
    let mut last_err = None;

    for addr in addrs {
        match timeout(timeout_duration, TcpStream::connect(addr)).await {
            Ok(Ok(_)) => return Ok(()),
            Ok(Err(e)) => last_err = Some(e),
            Err(_) => {
                last_err = Some(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Connection timed out",
                ))
            }
        }
    }
    Err(last_err.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "No addresses found")))
}

async fn grab_relays(
    preferred_urls: &[String],
    proxy: Option<&String>,
    timeout_duration: Duration,
) -> Result<Vec<Relay>> {
    let base_url = "https://onionoo.torproject.org/details?type=relay&running=true&fields=fingerprint,or_addresses,country";
    let mut urls = preferred_urls.to_vec();
    urls.insert(0, base_url.to_string());
    urls.push("https://raw.githubusercontent.com/nukeddd/tor-onionoo-mirror/refs/heads/master/details-running-relays-fingerprint-address-only.json".to_string());
    urls.push("https://bitbucket.org/ValdikSS/tor-onionoo-mirror/raw/master/details-running-relays-fingerprint-address-only.json".to_string());

    let mut client_builder = Client::builder().timeout(timeout_duration);
    if let Some(p) = proxy {
        client_builder = client_builder.proxy(reqwest::Proxy::all(p)?);
    }
    let client = client_builder.build()?;

    for url in &urls {
        eprintln!("Trying to download from {}...", url);
        match client.get(url).send().await {
            Ok(response) if response.status().is_success() => {
                match response.json::<OnionooResponse>().await {
                    Ok(json) => return Ok(json.relays),
                    Err(e) => eprintln!("-> Failed to parse JSON from {}: {}", url, e),
                }
            }
            Ok(response) => eprintln!(
                "-> Failed to download from {}: Status {}",
                url,
                response.status()
            ),
            Err(e) => eprintln!("-> Failed to download from {}: {}", url, e),
        }
    }

    Err(anyhow::anyhow!(
        "Tor Relay information can't be downloaded!"
    ))
}

async fn check_relay(relay: Relay, timeout_duration: Duration) -> (Relay, Vec<(String, u16)>) {
    let addresses = parse_or_addresses(&relay.or_addresses);
    let mut reachable_addrs = Vec::new();

    for (host, port) in &addresses {
        if check_connection(host, *port, timeout_duration)
            .await
            .is_ok()
        {
            reachable_addrs.push((host.clone(), *port));
        }
    }
    (relay, reachable_addrs)
}


/// Filters relays by port, returning a new list of relays with modified `or_addresses`.
fn filter_by_port(relays: &[Relay], ports: &[u16]) -> Vec<Relay> {
    if ports.is_empty() {
        return relays.to_vec();
    }

    relays
        .iter()
        .flat_map(|relay| {
            parse_or_addresses(&relay.or_addresses)
                .into_iter()
                .filter_map(move |(host, port)| {
                    if ports.contains(&port) {
                        let mut relay_copy = relay.clone();
                        relay_copy.or_addresses = vec![format_address(&host, port)];
                        Some(relay_copy)
                    } else {
                        None
                    }
                })
        })
        .collect()
}
#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    if let Some(path) = &args.outfile {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::File::create(path)?;
    }
    let timeout_duration = Duration::from_secs_f64(args.timeout);
    let bridge_prefix = if args.torrc_fmt { "Bridge " } else { "" };

    println!(
        "Tor Relay Scanner. Will scan for up to {} working relays.",
        args.working_relay_num_goal
    );
    println!("Downloading Tor Relay information...");

    let mut relays = grab_relays(&args.url, args.proxy.as_ref(), timeout_duration).await?;
    println!("Done! Found {} relays.", relays.len());

    relays = filter_by_port(&relays, &args.port);

    if relays.is_empty() {
        println!("No relays selected after filtering. Check your country/port constraints.");
        return Ok(());
    }

    relays.shuffle(&mut rand::thread_rng());

    let mut working_relays = Vec::new();
    let chunks: Vec<_> = relays.chunks(args.num_relays).collect();
    let num_tries = chunks.len();

    for (i, chunk) in chunks.iter().enumerate() {
        if working_relays.len() >= args.working_relay_num_goal {
            break;
        }

        println!(
            "\n--- Attempt {}/{} (testing {} relays) ---",
            i + 1,
            num_tries,
            chunk.len()
        );

        let mut stream = stream::iter(chunk.iter().cloned())
            .map(|r| tokio::spawn(check_relay(r, timeout_duration)))
            .buffer_unordered(args.num_relays);

        let mut found_in_attempt = false;
        while let Some(join_result) = stream.next().await {
            match join_result {
                Ok((relay, reachable_addrs)) => {
                    if !reachable_addrs.is_empty() {
                        if !found_in_attempt {
                            println!("Reachable relays in this attempt:");
                            found_in_attempt = true;
                        }
                        let mut out_str = String::new();
                        for (host, port) in &reachable_addrs {
                            let addr = format_address(host, *port);
                            out_str.push_str(&format!("{}{} {}\n", bridge_prefix, addr, relay.fingerprint));
                        }
                        if let Some(path) = &args.outfile {
                            let mut file = fs::OpenOptions::new().append(true).open(path)?;
                            file.write_all(out_str.as_bytes())?;
                        } else {
                            print!("{}", out_str);
                        }
                        working_relays.push((relay, reachable_addrs));
                    }
                }
                Err(e) => {
                    eprintln!("Task failed: {:?}", e);
                }
            }
        }
        if !found_in_attempt {
            println!("No relays were reachable in this attempt.");
        }
    }
    println!("\n--- Scan Complete ---");
    if working_relays.is_empty() {
        println!("No working relays found.");
    } else {
        println!("Found {} working relays in total.", working_relays.len());
        if let Some(path) = &args.outfile {
            println!("Results saved to {}", path.display());
            if args.torrc_fmt {
                let mut file = fs::OpenOptions::new().append(true).create(true).open(path)?;
                file.write_all(b"UseBridges 1\n")?;
            }
        } else if args.torrc_fmt {
            println!("Add the following line to your torrc file:\nUseBridges 1");
        }
    }

    println!("Done.");
    //stdin().read_line(&mut String::new())?;
    Ok(())
}
