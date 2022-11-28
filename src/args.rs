use crate::rust_scan::port_strategy::SerialRange;
use crate::rust_scan::ScanOrder;
use crate::PortRange;
use crate::PortStrategy;
use crate::Scanner;
use std::net::*;
use std::time::Duration;

pub struct Args {
    pub help: bool,
    pub addresses: Vec<SocketAddr>,
    pub payload: Vec<u8>,
}

fn str_to_ips(ip_str: String) -> Vec<Ipv4Addr> {
    let mut results = vec![];

    let ip_sub = ip_str
        .split(".")
        .map(|n| {
            if n == "*" {
                None
            } else {
                Some(n.to_string().parse::<u8>().unwrap())
            }
        })
        .collect::<Vec<Option<u8>>>();

    for n0 in 0..=255 {
        let n0 = ip_sub[0].unwrap_or(n0);
        for n1 in 0..=255 {
            let n1 = ip_sub[1].unwrap_or(n1);
            for n2 in 0..=255 {
                let n2 = ip_sub[2].unwrap_or(n2);
                for n3 in 0..=255 {
                    let n3 = ip_sub[3].unwrap_or(n3);

                    results.push(Ipv4Addr::new(n0, n1, n2, n3));

                    if let Some(n) = ip_sub[3] {
                        break;
                    }
                }
                if let Some(n) = ip_sub[2] {
                    break;
                }
            }
            if let Some(n) = ip_sub[1] {
                break;
            }
        }
        if let Some(n) = ip_sub[0] {
            break;
        }
    }

    return results;
}

async fn scan(ip: &IpAddr) -> Vec<SocketAddr> {
    let scanner = Scanner::new(
        &[*ip],
        16,
        Duration::from_millis(50),
        32,
        false,
        PortStrategy::pick(
            &Some(PortRange {
                start: u16::MIN,
                end: u16::MAX,
            }),
            None,
            ScanOrder::Serial,
        ),
        false,
    );

    scanner.run().await
}

pub async fn parse_cmd_args() -> Args {
    if std::env::args().any(|a| a == "-h" || a == "--help") {
        return Args {
            help: true,
            addresses: vec![],
            payload: vec![],
        };
    }

    let mut addresses = vec![];
    for ip_port_str in std::env::args().skip(1) {
        if ip_port_str == "--payload" {
            break;
        }
        let ip_str = ip_port_str.split(":").collect::<Vec<&str>>()[0];
        let ip_sub = ip_str.split(".").collect::<Vec<&str>>();

        if ip_sub.len() != 4 {
            panic!("invalid ip");
        }

        let ips = str_to_ips(ip_str.to_string());

        let port_str = ip_port_str.split(":").collect::<Vec<&str>>()[1];

        if port_str == "*" {
            let mut addrs = vec![];

            for ip in ips {
                let scaned_addrs = scan(&IpAddr::V4(ip)).await;

                for addr in scaned_addrs {
                    addrs.push(addr);
                }
            }
            addresses.push(addrs);
        } else {
            addresses.push(
                ips.iter()
                    .map(|ip: &Ipv4Addr| {
                        SocketAddr::new(
                            IpAddr::V4(*ip),
                            port_str.to_string().parse::<u16>().unwrap(),
                        )
                    })
                    .collect(),
            );
        }
    }

    let payload = std::env::args()
        .zip(std::env::args().skip(1))
        .find(|(flag, _)| flag == "--payload" || flag == "-p")
        .map(|(_, payload)| payload);

    if payload.is_none() {
        panic!("missing -p / --payload option");
    }

    let payload = payload.unwrap();

    return Args {
        help: false,
        addresses: addresses.iter().flatten().map(|s| *s).collect(),
        payload: Vec::from(payload),
    };
}
