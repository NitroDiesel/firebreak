//! The packets log file, and the TCP/UDP endpoint tables behind the
//! Connections tab (`_app_network_generatetable` in network.c).

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, GetPerTcp6ConnectionEStats, GetPerTcpConnectionEStats,
    SetPerTcp6ConnectionEStats, SetPerTcpConnectionEStats, TcpConnectionEstatsData, MIB_TCP6ROW, MIB_TCP6ROW_OWNER_PID,
    MIB_TCPROW_LH, MIB_TCPROW_LH_0, MIB_TCPROW_OWNER_PID, MIB_TCP_STATE, MIB_UDP6ROW_OWNER_PID, MIB_UDPROW_OWNER_PID,
    TCP_ESTATS_DATA_ROD_v0, TCP_ESTATS_DATA_RW_v0, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6, IN6_ADDR, IN6_ADDR_0};

/// PROC_WAITING_PID: sockets closing on behalf of a process that has exited.
const WAITING_PID: u32 = 0;
const SYSTEM_PID: u32 = 4;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub name: String,
    /// Executable path, "System", or empty when unknown.
    pub path: String,
    pub proto: &'static str,
    pub local: String,
    pub remote: String,
    /// Remote address, for host name lookups. None for listeners.
    pub remote_ip: Option<IpAddr>,
    pub state: &'static str,
    pub pid: u32,
    /// Local port, to match UDP traffic to its socket.
    pub local_port: u16,
    /// Bytes received and sent so far, when traffic statistics are on.
    pub bytes: Option<(u64, u64)>,
    /// Speeds and total, worked out by the monitor between two readings.
    pub traffic: Option<Traffic>,
}

/// Traffic of one connection (download_speed, upload_speed, and total in network.c).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Traffic {
    pub down_per_sec: u64,
    pub up_per_sec: u64,
    pub total: u64,
}

impl Endpoint {
    /// An established connection to somewhere other than this machine; the
    /// C build highlights its app (IsHighlightConnection).
    pub fn is_live(&self) -> bool {
        self.state == "Established" && self.remote_ip.is_some_and(|ip| !ip.is_loopback() && !ip.is_unspecified())
    }
}

/// Every TCP connection in any state, and every UDP endpoint.
/// `show_waiting` keeps connections that belong to no process any more
/// (IsNetworkShowWaitConnections). `tcp_stats` reads byte counts of established
/// TCP connections, which needs administrator rights.
pub fn connections(show_waiting: bool, tcp_stats: bool) -> Vec<Endpoint> {
    let mut rows = Vec::new();
    tcp_v4(&mut rows, tcp_stats);
    tcp_v6(&mut rows, tcp_stats);
    udp_v4(&mut rows);
    udp_v6(&mut rows);
    if !show_waiting {
        rows.retain(|row| row.pid != WAITING_PID);
    }
    let names = crate::apps::process_names();
    let mut paths: HashMap<u32, String> = HashMap::new();
    for row in &mut rows {
        (row.name, row.path) = match row.pid {
            WAITING_PID => ("Waiting connections".into(), String::new()),
            SYSTEM_PID => (crate::model::SYSTEM_APP.into(), crate::model::SYSTEM_APP.into()),
            pid => {
                let path = paths
                    .entry(pid)
                    .or_insert_with(|| crate::apps::process_path(pid).unwrap_or_default())
                    .clone();
                let name = names.get(&pid).cloned().unwrap_or_else(|| format!("PID {pid}"));
                (name, path)
            }
        };
    }
    rows
}

pub fn append_file(path: &std::path::Path, line: &str) {
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(file, "{line}");
    }
}

pub fn log_path() -> std::path::PathBuf {
    if let Ok(profile) = std::env::var("USERPROFILE") {
        return std::path::PathBuf::from(profile).join("simplewall.csv");
    }
    std::path::PathBuf::from("simplewall.csv")
}

/// MIB_TCP_STATE names.
fn tcp_state(state: u32) -> &'static str {
    match state {
        1 => "Closed",
        2 => "Listening",
        3 => "SYN sent",
        4 => "SYN received",
        5 => "Established",
        6 => "FIN wait 1",
        7 => "FIN wait 2",
        8 => "Close wait",
        9 => "Closing",
        10 => "Last ACK",
        11 => "Time wait",
        12 => "Delete TCB",
        _ => "",
    }
}

fn endpoint(ip: IpAddr, port: u16) -> String {
    match ip {
        IpAddr::V4(v4) => format!("{v4}:{port}"),
        IpAddr::V6(v6) => format!("[{v6}]:{port}"),
    }
}

fn row(proto: &'static str, local: (IpAddr, u16), remote: Option<(IpAddr, u16)>, state: &'static str, pid: u32) -> Endpoint {
    Endpoint {
        name: String::new(),
        path: String::new(),
        proto,
        local: endpoint(local.0, local.1),
        remote: remote.map_or_else(|| "*".into(), |(ip, port)| endpoint(ip, port)),
        remote_ip: remote.map(|(ip, _)| ip),
        state,
        pid,
        local_port: local.1,
        bytes: None,
        traffic: None,
    }
}

fn port(raw: u32) -> u16 {
    u16::from_be(raw as u16)
}

fn tcp_v4(out: &mut Vec<Endpoint>, stats: bool) {
    let Some(buf) = table(AF_INET.0 as u32, true) else {
        return;
    };
    unsafe {
        let count = *(buf.as_ptr() as *const u32);
        let rows = buf.as_ptr().add(4) as *const MIB_TCPROW_OWNER_PID;
        for i in 0..count as usize {
            let r = &*rows.add(i);
            let listening = r.dwState == 2;
            let remote = (!listening).then(|| (IpAddr::V4(ipv4(r.dwRemoteAddr)), port(r.dwRemotePort)));
            out.push(row(
                "tcp",
                (IpAddr::V4(ipv4(r.dwLocalAddr)), port(r.dwLocalPort)),
                remote,
                tcp_state(r.dwState),
                r.dwOwningPid,
            ));
            if stats && r.dwState == ESTABLISHED {
                if let Some(last) = out.last_mut() {
                    last.bytes = tcp4_bytes(r);
                }
            }
        }
    }
}

fn tcp_v6(out: &mut Vec<Endpoint>, stats: bool) {
    let Some(buf) = table(AF_INET6.0 as u32, true) else {
        return;
    };
    unsafe {
        let count = *(buf.as_ptr() as *const u32);
        let rows = buf.as_ptr().add(4) as *const MIB_TCP6ROW_OWNER_PID;
        for i in 0..count as usize {
            let r = &*rows.add(i);
            let listening = r.dwState == 2;
            let remote = (!listening).then(|| (IpAddr::V6(Ipv6Addr::from(r.ucRemoteAddr)), port(r.dwRemotePort)));
            out.push(row(
                "tcp6",
                (IpAddr::V6(Ipv6Addr::from(r.ucLocalAddr)), port(r.dwLocalPort)),
                remote,
                tcp_state(r.dwState),
                r.dwOwningPid,
            ));
            if stats && r.dwState == ESTABLISHED {
                if let Some(last) = out.last_mut() {
                    last.bytes = tcp6_bytes(r);
                }
            }
        }
    }
}

const ESTABLISHED: u32 = 5;

/// Bytes in and out of one IPv4 connection, turning collection on first, as
/// `_app_network_update_tcp4_stats` does. Needs administrator rights.
unsafe fn tcp4_bytes(r: &MIB_TCPROW_OWNER_PID) -> Option<(u64, u64)> {
    let row = MIB_TCPROW_LH {
        Anonymous: MIB_TCPROW_LH_0 { dwState: r.dwState },
        dwLocalAddr: r.dwLocalAddr,
        dwLocalPort: r.dwLocalPort,
        dwRemoteAddr: r.dwRemoteAddr,
        dwRemotePort: r.dwRemotePort,
    };
    let on = TCP_ESTATS_DATA_RW_v0 { EnableCollection: true };
    let _ = SetPerTcpConnectionEStats(&row, TcpConnectionEstatsData, as_bytes(&on), 0, 0);
    let mut rw = TCP_ESTATS_DATA_RW_v0::default();
    let mut rod = TCP_ESTATS_DATA_ROD_v0::default();
    let status = GetPerTcpConnectionEStats(&row, TcpConnectionEstatsData, Some(as_bytes_mut(&mut rw)), 0, None, 0, Some(as_bytes_mut(&mut rod)), 0);
    (status == 0 && rw.EnableCollection).then_some((rod.DataBytesIn, rod.DataBytesOut))
}

/// The IPv6 version of `tcp4_bytes`.
unsafe fn tcp6_bytes(r: &MIB_TCP6ROW_OWNER_PID) -> Option<(u64, u64)> {
    let row = MIB_TCP6ROW {
        State: MIB_TCP_STATE(r.dwState as i32),
        LocalAddr: IN6_ADDR { u: IN6_ADDR_0 { Byte: r.ucLocalAddr } },
        dwLocalScopeId: r.dwLocalScopeId,
        dwLocalPort: r.dwLocalPort,
        RemoteAddr: IN6_ADDR { u: IN6_ADDR_0 { Byte: r.ucRemoteAddr } },
        dwRemoteScopeId: r.dwRemoteScopeId,
        dwRemotePort: r.dwRemotePort,
    };
    let on = TCP_ESTATS_DATA_RW_v0 { EnableCollection: true };
    let _ = SetPerTcp6ConnectionEStats(&row, TcpConnectionEstatsData, as_bytes(&on), 0, 0);
    let mut rw = TCP_ESTATS_DATA_RW_v0::default();
    let mut rod = TCP_ESTATS_DATA_ROD_v0::default();
    let status = GetPerTcp6ConnectionEStats(&row, TcpConnectionEstatsData, Some(as_bytes_mut(&mut rw)), 0, None, 0, Some(as_bytes_mut(&mut rod)), 0);
    (status == 0 && rw.EnableCollection).then_some((rod.DataBytesIn, rod.DataBytesOut))
}

unsafe fn as_bytes<T>(value: &T) -> &[u8] {
    std::slice::from_raw_parts(value as *const T as *const u8, std::mem::size_of::<T>())
}

unsafe fn as_bytes_mut<T>(value: &mut T) -> &mut [u8] {
    std::slice::from_raw_parts_mut(value as *mut T as *mut u8, std::mem::size_of::<T>())
}

fn udp_v4(out: &mut Vec<Endpoint>) {
    let Some(buf) = table(AF_INET.0 as u32, false) else {
        return;
    };
    unsafe {
        let count = *(buf.as_ptr() as *const u32);
        let rows = buf.as_ptr().add(4) as *const MIB_UDPROW_OWNER_PID;
        for i in 0..count as usize {
            let r = &*rows.add(i);
            out.push(row("udp", (IpAddr::V4(ipv4(r.dwLocalAddr)), port(r.dwLocalPort)), None, "", r.dwOwningPid));
        }
    }
}

fn udp_v6(out: &mut Vec<Endpoint>) {
    let Some(buf) = table(AF_INET6.0 as u32, false) else {
        return;
    };
    unsafe {
        let count = *(buf.as_ptr() as *const u32);
        let rows = buf.as_ptr().add(4) as *const MIB_UDP6ROW_OWNER_PID;
        for i in 0..count as usize {
            let r = &*rows.add(i);
            out.push(row(
                "udp6",
                (IpAddr::V6(Ipv6Addr::from(r.ucLocalAddr)), port(r.dwLocalPort)),
                None,
                "",
                r.dwOwningPid,
            ));
        }
    }
}

fn table(family: u32, tcp: bool) -> Option<Vec<u8>> {
    unsafe {
        // The table can grow between the size query and the read; retry a few times.
        let mut size = 0u32;
        for _ in 0..4 {
            let mut buf = vec![0u8; size as usize + 1024];
            size = buf.len() as u32;
            let err = if tcp {
                GetExtendedTcpTable(Some(buf.as_mut_ptr() as *mut _), &mut size, false, family, TCP_TABLE_OWNER_PID_ALL, 0)
            } else {
                GetExtendedUdpTable(Some(buf.as_mut_ptr() as *mut _), &mut size, false, family, UDP_TABLE_OWNER_PID, 0)
            };
            if err == 0 {
                return Some(buf);
            }
        }
        None
    }
}

fn ipv4(addr: u32) -> Ipv4Addr {
    Ipv4Addr::from(addr.to_le_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_table_reads_and_names_states() {
        let rows = connections(true, false);
        assert!(!rows.is_empty());
        assert!(rows.iter().all(|r| !r.name.is_empty()));
        assert!(rows.iter().filter(|r| r.proto.starts_with("tcp")).all(|r| !r.state.is_empty()));
        assert!(!connections(false, false).iter().any(|r| r.pid == WAITING_PID));
    }
}
