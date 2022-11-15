#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::doc_markdown, clippy::if_not_else, clippy::non_ascii_literal)]

mod tui;

pub mod input;
pub use input::{Config, Opts, PortRange, ScanOrder, ScriptsRequired};

pub mod scanner;
pub use scanner::Scanner;

pub mod port_strategy;
pub use port_strategy::PortStrategy;

mod scripts;
use scripts::{init_scripts, Script, ScriptFile};

use cidr_utils::cidr::IpCidr;
use colorful::{Color, Colorful};
use futures::executor::block_on;
use rlimit::{getrlimit, setrlimit, RawRlim, Resource, Rlim};
use std::collections::HashMap;
use std::convert::TryInto;
use std::fs::File;
use std::io::{prelude::*, BufReader};
use std::net::{IpAddr, ToSocketAddrs};
use std::path::Path;
use std::string::ToString;
use std::time::Duration;
use trust_dns_resolver::{
    config::{ResolverConfig, ResolverOpts},
    Resolver,
};

extern crate colorful;
extern crate dirs;

// Average value for Ubuntu
const DEFAULT_FILE_DESCRIPTORS_LIMIT: RawRlim = 8000;
// Safest batch size based on experimentation
const AVERAGE_BATCH_SIZE: RawRlim = 3000;

/// Terminal User Interface Module for RustScan
/// Defines macros to use

#[macro_export]
macro_rules! warning {
    ($name:expr) => {
        use ansi_term::Colour::Red;
        println!("{} {}", Red.bold().paint("[!]"), $name);
    };
    ($name:expr, $greppable:expr, $accessible:expr) => {
        use ansi_term::Colour::Red;
        // if not greppable then print, otherwise no else statement so do not print.
        if !$greppable {
            if $accessible {
                // Don't print the ascii art
                println!("{}", $name);
            } else {
                println!("{} {}", Red.bold().paint("[!]"), $name);
            }
        }
    };
}

#[macro_export]
macro_rules! detail {
    ($name:expr) => {
        use ansi_term::Colour::Blue;
        println!("{} {}", Blue.bold().paint("[~]"), $name);
    };
    ($name:expr, $greppable:expr, $accessible:expr) => {
        use ansi_term::Colour::Blue;
        // if not greppable then print, otherwise no else statement so do not print.
        if !$greppable {
            if $accessible {
                // Don't print the ascii art
                println!("{}", $name);
            } else {
                println!("{} {}", Blue.bold().paint("[~]"), $name);
            }
        }
    };
}

#[macro_export]
macro_rules! output {
    ($name:expr) => {
        use ansi_term::Colour::RGB;
        println!("{} {}", RGB(0, 255, 9).bold().paint("[>]"), $name);
    };
    ($name:expr, $greppable:expr, $accessible:expr) => {
        use ansi_term::Colour::RGB;
        // if not greppable then print, otherwise no else statement so do not print.
        if !$greppable {
            if $accessible {
                // Don't print the ascii art
                println!("{}", $name);
            } else {
                println!("{} {}", RGB(0, 255, 9).bold().paint("[>]"), $name);
            }
        }
    };
}

#[macro_export]
macro_rules! funny_opening {
    // prints a funny quote / opening
    () => {
        use rand::seq::SliceRandom;
        let quotes = vec![
            "Nmap? More like slowmap.🐢",
            "🌍HACK THE PLANET🌍",
            "Real hackers hack time ⌛",
            "Please contribute more quotes to our GitHub https://github.com/rustscan/rustscan",
            "😵 https://admin.tryhackme.com",
            "0day was here ♥",
        ];
        let random_quote = quotes.choose(&mut rand::thread_rng()).unwrap();

        println!("{}\n", random_quote);
        // println!("{} {}", RGB(0, 255, 9).bold().paint("[>]"), $name);
    };
}

/// Goes through all possible IP inputs (files or via argparsing)
/// Parses the string(s) into IPs
fn parse_addresses(input: &Opts) -> Vec<IpAddr> {
    let mut ips: Vec<IpAddr> = Vec::new();
    let mut unresolved_addresses: Vec<&str> = Vec::new();
    let backup_resolver =
        Resolver::new(ResolverConfig::cloudflare_tls(), ResolverOpts::default()).unwrap();

    for address in &input.addresses {
        let parsed_ips = parse_address(address, &backup_resolver);
        if !parsed_ips.is_empty() {
            ips.extend(parsed_ips);
        } else {
            unresolved_addresses.push(address);
        }
    }

    // If we got to this point this can only be a file path or the wrong input.
    for file_path in unresolved_addresses {
        let file_path = Path::new(file_path);

        if !file_path.is_file() {
            warning!(
                format!("Host {:?} could not be resolved.", file_path),
                input.greppable,
                input.accessible
            );

            continue;
        }

        if let Ok(x) = read_ips_from_file(file_path, &backup_resolver) {
            ips.extend(x);
        } else {
            warning!(
                format!("Host {:?} could not be resolved.", file_path),
                input.greppable,
                input.accessible
            );
        }
    }

    ips
}

/// Given a string, parse it as an host, IP address, or CIDR.
/// This allows us to pass files as hosts or cidr or IPs easily
/// Call this everytime you have a possible IP_or_host
fn parse_address(address: &str, resolver: &Resolver) -> Vec<IpAddr> {
    IpCidr::from_str(&address)
        .map(|cidr| cidr.iter().collect())
        .ok()
        .or_else(|| {
            format!("{}:{}", &address, 80)
                .to_socket_addrs()
                .ok()
                .map(|mut iter| vec![iter.next().unwrap().ip()])
        })
        .unwrap_or_else(|| resolve_ips_from_host(address, resolver))
}

/// Uses DNS to get the IPS assiocated with host
fn resolve_ips_from_host(source: &str, backup_resolver: &Resolver) -> Vec<IpAddr> {
    let mut ips: Vec<std::net::IpAddr> = Vec::new();

    if let Ok(addrs) = source.to_socket_addrs() {
        for ip in addrs {
            ips.push(ip.ip());
        }
    } else if let Ok(addrs) = backup_resolver.lookup_ip(source) {
        ips.extend(addrs.iter());
    }

    ips
}

#[cfg(not(tarpaulin_include))]
/// Parses an input file of IPs and uses those
fn read_ips_from_file(
    ips: &std::path::Path,
    backup_resolver: &Resolver,
) -> Result<Vec<std::net::IpAddr>, std::io::Error> {
    let file = File::open(ips)?;
    let reader = BufReader::new(file);

    let mut ips: Vec<std::net::IpAddr> = Vec::new();

    for address_line in reader.lines() {
        if let Ok(address) = address_line {
            ips.extend(parse_address(&address, backup_resolver));
        } else {
            debug!("Line in file is not valid");
        }
    }

    Ok(ips)
}

fn adjust_ulimit_size(opts: &Opts) -> RawRlim {
    if opts.ulimit.is_some() {
        let limit: Rlim = Rlim::from_raw(opts.ulimit.unwrap());

        if setrlimit(Resource::NOFILE, limit, limit).is_ok() {
            detail!(
                format!("Automatically increasing ulimit value to {}.", limit),
                opts.greppable,
                opts.accessible
            );
        } else {
            warning!(
                "ERROR. Failed to set ulimit value.",
                opts.greppable,
                opts.accessible
            );
        }
    }

    let (rlim, _) = getrlimit(Resource::NOFILE).unwrap();

    rlim.as_raw()
}

fn infer_batch_size(opts: &Opts, ulimit: RawRlim) -> u16 {
    let mut batch_size: RawRlim = opts.batch_size.into();

    // Adjust the batch size when the ulimit value is lower than the desired batch size
    if ulimit < batch_size {
        warning!("File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers",
            opts.greppable, opts.accessible
        );

        // When the OS supports high file limits like 8000, but the user
        // selected a batch size higher than this we should reduce it to
        // a lower number.
        if ulimit < AVERAGE_BATCH_SIZE {
            // ulimit is smaller than aveage batch size
            // user must have very small ulimit
            // decrease batch size to half of ulimit
            warning!("Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. ", opts.greppable, opts.accessible);
            info!("Halving batch_size because ulimit is smaller than average batch size");
            batch_size = ulimit / 2;
        } else if ulimit > DEFAULT_FILE_DESCRIPTORS_LIMIT {
            info!("Batch size is now average batch size");
            batch_size = AVERAGE_BATCH_SIZE;
        } else {
            batch_size = ulimit - 100;
        }
    }
    // When the ulimit is higher than the batch size let the user know that the
    // batch size can be increased unless they specified the ulimit themselves.
    else if ulimit + 2 > batch_size && (opts.ulimit.is_none()) {
        detail!(format!("File limit higher than batch size. Can increase speed by increasing batch size '-b {}'.", ulimit - 100),
        opts.greppable, opts.accessible);
    }

    batch_size
        .try_into()
        .expect("Couldn't fit the batch size into a u16.")
}

#[cfg(test)]
mod tests {
    use crate::rust_scan::{adjust_ulimit_size, infer_batch_size, parse_addresses, Opts};
    use std::net::Ipv4Addr;

    #[test]
    fn batch_size_lowered() {
        let mut opts = Opts::default();
        opts.batch_size = 50_000;
        let batch_size = infer_batch_size(&opts, 120);

        assert!(batch_size < opts.batch_size);
    }

    #[test]
    fn batch_size_lowered_average_size() {
        let mut opts = Opts::default();
        opts.batch_size = 50_000;
        let batch_size = infer_batch_size(&opts, 9_000);

        assert!(batch_size == 3_000);
    }
    #[test]
    fn batch_size_equals_ulimit_lowered() {
        // because ulimit and batch size are same size, batch size is lowered
        // to ULIMIT - 100
        let mut opts = Opts::default();
        opts.batch_size = 50_000;
        let batch_size = infer_batch_size(&opts, 5_000);

        assert!(batch_size == 4_900);
    }
    #[test]
    fn batch_size_adjusted_2000() {
        // ulimit == batch_size
        let mut opts = Opts::default();
        opts.batch_size = 50_000;
        opts.ulimit = Some(2_000);
        let batch_size = adjust_ulimit_size(&opts);

        assert!(batch_size == 2_000);
    }

    #[test]
    fn test_high_ulimit_no_greppable_mode() {
        let mut opts = Opts::default();
        opts.batch_size = 10;
        opts.greppable = false;

        let batch_size = infer_batch_size(&opts, 1_000_000);

        assert!(batch_size == opts.batch_size);
    }

    #[test]
    fn parse_correct_addresses() {
        let mut opts = Opts::default();
        opts.addresses = vec!["127.0.0.1".to_owned(), "192.168.0.0/30".to_owned()];
        let ips = parse_addresses(&opts);

        assert_eq!(
            ips,
            [
                Ipv4Addr::new(127, 0, 0, 1),
                Ipv4Addr::new(192, 168, 0, 0),
                Ipv4Addr::new(192, 168, 0, 1),
                Ipv4Addr::new(192, 168, 0, 2),
                Ipv4Addr::new(192, 168, 0, 3)
            ]
        );
    }

    #[test]
    fn parse_correct_host_addresses() {
        let mut opts = Opts::default();
        opts.addresses = vec!["google.com".to_owned()];
        let ips = parse_addresses(&opts);

        assert_eq!(ips.len(), 1);
    }

    #[test]
    fn parse_correct_and_incorrect_addresses() {
        let mut opts = Opts::default();
        opts.addresses = vec!["127.0.0.1".to_owned(), "im_wrong".to_owned()];
        let ips = parse_addresses(&opts);

        assert_eq!(ips, [Ipv4Addr::new(127, 0, 0, 1),]);
    }

    #[test]
    fn parse_incorrect_addresses() {
        let mut opts = Opts::default();
        opts.addresses = vec!["im_wrong".to_owned(), "300.10.1.1".to_owned()];
        let ips = parse_addresses(&opts);

        assert_eq!(ips.is_empty(), true);
    }
    #[test]
    fn parse_hosts_file_and_incorrect_hosts() {
        // Host file contains IP, Hosts, incorrect IPs, incorrect hosts
        let mut opts = Opts::default();
        opts.addresses = vec!["fixtures/hosts.txt".to_owned()];
        let ips = parse_addresses(&opts);
        assert_eq!(ips.len(), 3);
    }

    #[test]
    fn parse_empty_hosts_file() {
        // Host file contains IP, Hosts, incorrect IPs, incorrect hosts
        let mut opts = Opts::default();
        opts.addresses = vec!["fixtures/empty_hosts.txt".to_owned()];
        let ips = parse_addresses(&opts);
        assert_eq!(ips.len(), 0);
    }

    #[test]
    fn parse_naughty_host_file() {
        // Host file contains IP, Hosts, incorrect IPs, incorrect hosts
        let mut opts = Opts::default();
        opts.addresses = vec!["fixtures/naughty_string.txt".to_owned()];
        let ips = parse_addresses(&opts);
        assert_eq!(ips.len(), 0);
    }
}
