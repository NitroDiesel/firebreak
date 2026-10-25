//! The network monitor (IsNetworkMonitorEnabled): reads the connection tables
//! every 2 seconds on its own thread, as `_app_network_threadproc` does, and
//! only wakes the window when something changed. Host names for remote
//! addresses are looked up on another thread (IsNetworkResolutionsEnabled).
//! With traffic statistics on, it also works out each connection's speeds
//! from two readings, like `_app_network_update_stats_values`.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use eframe::egui;

use crate::log::{self, Endpoint, Traffic};
use crate::udptrace::UdpTrace;

const PERIOD: Duration = Duration::from_secs(2);

/// What the monitor collects; the window updates it every frame.
#[derive(Default)]
struct Switches {
    enabled: AtomicBool,
    show_waiting: AtomicBool,
    /// TCP byte counts (needs administrator rights).
    tcp_stats: AtomicBool,
    /// UDP byte counts from the kernel network trace (IsUdpTrafficEnabled).
    udp_stats: AtomicBool,
}

pub struct Monitor {
    rx: Receiver<Vec<Endpoint>>,
    switches: Arc<Switches>,
}

impl Monitor {
    pub fn spawn(ctx: egui::Context, enabled: bool, show_waiting: bool) -> Self {
        let (tx, rx) = channel();
        let switches = Arc::new(Switches::default());
        switches.enabled.store(enabled, Ordering::Relaxed);
        switches.show_waiting.store(show_waiting, Ordering::Relaxed);
        let on = switches.clone();
        std::thread::spawn(move || {
            let mut last: Vec<Endpoint> = Vec::new();
            let mut udp: Option<UdpTrace> = None;
            let mut previous: HashMap<String, (u64, u64, Instant)> = HashMap::new();
            loop {
                let want_udp = on.udp_stats.load(Ordering::Relaxed);
                if want_udp && udp.is_none() {
                    udp = UdpTrace::start().ok();
                } else if !want_udp {
                    udp = None;
                }
                if on.enabled.load(Ordering::Relaxed) {
                    let tcp = on.tcp_stats.load(Ordering::Relaxed);
                    let mut rows = log::connections(on.show_waiting.load(Ordering::Relaxed), tcp);
                    if let Some(trace) = &udp {
                        let totals = trace.totals();
                        for row in rows.iter_mut().filter(|r| r.proto.starts_with("udp")) {
                            row.bytes = Some(totals.get(&(row.pid, row.local_port)).copied().unwrap_or_default());
                        }
                    }
                    add_traffic(&mut rows, &mut previous);
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
        Self { rx, switches }
    }

    pub fn configure(&self, enabled: bool, show_waiting: bool, tcp_stats: bool, udp_stats: bool) {
        let s = &self.switches;
        s.enabled.store(enabled, Ordering::Relaxed);
        s.show_waiting.store(show_waiting, Ordering::Relaxed);
        s.tcp_stats.store(tcp_stats, Ordering::Relaxed);
        s.udp_stats.store(udp_stats, Ordering::Relaxed);
    }

    /// The newest table, if one arrived since the last call.
    pub fn latest(&self) -> Option<Vec<Endpoint>> {
        self.rx.try_iter().last()
    }
}

/// Speeds from the change since the previous reading of the same connection.
fn add_traffic(rows: &mut [Endpoint], previous: &mut HashMap<String, (u64, u64, Instant)>) {
    let now = Instant::now();
    let mut next = HashMap::new();
    for row in rows.iter_mut() {
        let Some((down, up)) = row.bytes else {
            continue;
        };
        let key = format!("{}|{}|{}|{}", row.proto, row.local, row.remote, row.pid);
        let mut traffic = Traffic { total: down + up, ..Default::default() };
        if let Some((last_down, last_up, at)) = previous.get(&key) {
            let ms = now.duration_since(*at).as_millis().max(1) as u64;
            traffic.down_per_sec = down.saturating_sub(*last_down) * 1000 / ms;
            traffic.up_per_sec = up.saturating_sub(*last_up) * 1000 / ms;
        }
        row.traffic = Some(traffic);
        next.insert(key, (down, up, now));
    }
    *previous = next;
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
