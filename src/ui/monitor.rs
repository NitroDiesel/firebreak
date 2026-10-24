//! The network monitor (IsNetworkMonitorEnabled): reads the connection tables
//! every 2 seconds on its own thread, as `_app_network_threadproc` does, and
//! only wakes the window when something changed. Host names for remote
//! addresses are looked up on another thread (IsNetworkResolutionsEnabled).

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use eframe::egui;

use crate::log::{self, Endpoint};

const PERIOD: Duration = Duration::from_secs(2);

pub struct Monitor {
    rx: Receiver<Vec<Endpoint>>,
    enabled: Arc<AtomicBool>,
    show_waiting: Arc<AtomicBool>,
}

impl Monitor {
    pub fn spawn(ctx: egui::Context, enabled: bool, show_waiting: bool) -> Self {
        let (tx, rx) = channel();
        let on = Arc::new(AtomicBool::new(enabled));
        let waiting = Arc::new(AtomicBool::new(show_waiting));
        let (on2, waiting2) = (on.clone(), waiting.clone());
        std::thread::spawn(move || {
            let mut last: Vec<Endpoint> = Vec::new();
            loop {
                if on2.load(Ordering::Relaxed) {
                    let rows = log::connections(waiting2.load(Ordering::Relaxed));
                    if rows != last {
                        if tx.send(rows.clone()).is_err() {
                            break;
                        }
                        last = rows;
                        ctx.request_repaint();
                    }
                }
                std::thread::sleep(PERIOD);
            }
        });
        Self { rx, enabled: on, show_waiting: waiting }
    }

    pub fn configure(&self, enabled: bool, show_waiting: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
        self.show_waiting.store(show_waiting, Ordering::Relaxed);
    }

    /// The newest table, if one arrived since the last call.
    pub fn latest(&self) -> Option<Vec<Endpoint>> {
        self.rx.try_iter().last()
    }
}

pub struct Resolver {
    tx: Sender<IpAddr>,
    cache: Arc<Mutex<HashMap<IpAddr, Option<String>>>>,
    asked: HashSet<IpAddr>,
    version: Arc<AtomicU64>,
    seen: u64,
}

impl Resolver {
    pub fn spawn(ctx: egui::Context) -> Self {
        let (tx, rx) = channel::<IpAddr>();
        let cache = Arc::new(Mutex::new(HashMap::new()));
        let version = Arc::new(AtomicU64::new(0));
        // An address with no PTR record takes seconds to time out, so a few
        // lookups run at once.
        winsock::startup();
        let rx = Arc::new(Mutex::new(rx));
        for _ in 0..4 {
            let (rx, out, bump, ctx) = (rx.clone(), cache.clone(), version.clone(), ctx.clone());
            std::thread::spawn(move || loop {
                let Ok(ip) = rx.lock().unwrap().recv() else {
                    break;
                };
                let name = winsock::reverse_lookup(ip);
                out.lock().unwrap().insert(ip, name);
                bump.fetch_add(1, Ordering::Relaxed);
                ctx.request_repaint();
            });
        }
        Self { tx, cache, asked: HashSet::new(), version, seen: 0 }
    }

    /// Host name for an address: None until looked up, then Some(None) if it has none.
    pub fn host(&mut self, ip: IpAddr) -> Option<Option<String>> {
        if ip.is_loopback() || ip.is_unspecified() {
            return Some(None);
        }
        if self.asked.insert(ip) {
            let _ = self.tx.send(ip);
        }
        self.cache.lock().unwrap().get(&ip).cloned()
    }

    pub fn hosts(&self) -> HashMap<IpAddr, Option<String>> {
        self.cache.lock().unwrap().clone()
    }

    pub fn ask(&mut self, ip: IpAddr) {
        if !ip.is_loopback() && !ip.is_unspecified() && self.asked.insert(ip) {
            let _ = self.tx.send(ip);
        }
    }

    /// True once per batch of new answers.
    pub fn changed(&mut self) -> bool {
        let now = self.version.load(Ordering::Relaxed);
        let changed = now != self.seen;
        self.seen = now;
        changed
    }
}

mod winsock {
    use std::net::IpAddr;

    use windows::Win32::Networking::WinSock::{
        GetNameInfoW, WSAStartup, AF_INET, AF_INET6, IN6_ADDR, IN6_ADDR_0, IN_ADDR, IN_ADDR_0, NI_NAMEREQD, SOCKADDR,
        SOCKADDR_IN, SOCKADDR_IN6, WSADATA, socklen_t,
    };

    pub fn startup() {
        let mut data = WSADATA::default();
        unsafe {
            let _ = WSAStartup(0x0202, &mut data);
        }
    }

    /// PTR lookup through the system resolver. None when there is no name.
    pub fn reverse_lookup(ip: IpAddr) -> Option<String> {
        let mut host = [0u16; 1025];
        let status = unsafe {
            match ip {
                IpAddr::V4(v4) => {
                    let addr = SOCKADDR_IN {
                        sin_family: AF_INET,
                        sin_addr: IN_ADDR { S_un: IN_ADDR_0 { S_addr: u32::from_ne_bytes(v4.octets()) } },
                        ..Default::default()
                    };
                    GetNameInfoW(
                        &addr as *const _ as *const SOCKADDR,
                        socklen_t(std::mem::size_of::<SOCKADDR_IN>() as i32),
                        Some(&mut host),
                        None,
                        NI_NAMEREQD as i32,
                    )
                }
                IpAddr::V6(v6) => {
                    let addr = SOCKADDR_IN6 {
                        sin6_family: AF_INET6,
                        sin6_addr: IN6_ADDR { u: IN6_ADDR_0 { Byte: v6.octets() } },
                        ..Default::default()
                    };
                    GetNameInfoW(
                        &addr as *const _ as *const SOCKADDR,
                        socklen_t(std::mem::size_of::<SOCKADDR_IN6>() as i32),
                        Some(&mut host),
                        None,
                        NI_NAMEREQD as i32,
                    )
                }
            }
        };
        (status == 0).then(|| crate::apps::utf16_prefix(&host)).filter(|name| !name.is_empty())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn loopback_has_a_name() {
            startup();
            // 127.0.0.1 resolves to this machine's name without the network.
            assert!(reverse_lookup("127.0.0.1".parse().unwrap()).is_some());
        }
    }
}
