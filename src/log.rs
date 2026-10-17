//! Apply log and a snapshot of TCP/UDP endpoints (the connection list).

use std::fs::OpenOptions;
use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr};

use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP_STATE_ESTAB, MIB_TCPROW_OWNER_PID,
    MIB_TCP6ROW_OWNER_PID, MIB_UDPROW_OWNER_PID, MIB_UDP6ROW_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
    UDP_TABLE_OWNER_PID,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};

#[derive(Clone, Debug)]
pub struct Endpoint {
    pub proto: &'static str,
    pub local: String,
    pub remote: String,
    pub state: String,
    pub pid: u32,
}

pub fn connections() -> Vec<Endpoint> {
    let mut rows = Vec::new();
    tcp_v4(&mut rows);
    tcp_v6(&mut rows);
    udp_v4(&mut rows);
    udp_v6(&mut rows);
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

fn tcp_v4(out: &mut Vec<Endpoint>) {
    let Some(buf) = table(AF_INET.0 as u32, true, false) else {
        return;
    };
    unsafe {
        let count = *(buf.as_ptr() as *const u32);
        let rows = buf.as_ptr().add(4) as *const MIB_TCPROW_OWNER_PID;
        for i in 0..count as usize {
            let row = &*rows.add(i);
            if row.dwState != MIB_TCP_STATE_ESTAB.0 as u32 {
                continue;
            }
            out.push(Endpoint {
                proto: "TCP",
                local: format!("{}:{}", ipv4(row.dwLocalAddr), u16::from_be(row.dwLocalPort as u16)),
                remote: format!("{}:{}", ipv4(row.dwRemoteAddr), u16::from_be(row.dwRemotePort as u16)),
                state: "Established".into(),
                pid: row.dwOwningPid,
            });
        }
    }
}

fn tcp_v6(out: &mut Vec<Endpoint>) {
    let Some(buf) = table(AF_INET6.0 as u32, true, true) else {
        return;
    };
    unsafe {
        let count = *(buf.as_ptr() as *const u32);
        let rows = buf.as_ptr().add(4) as *const MIB_TCP6ROW_OWNER_PID;
        for i in 0..count as usize {
            let row = &*rows.add(i);
            if row.dwState != MIB_TCP_STATE_ESTAB.0 as u32 {
                continue;
            }
            out.push(Endpoint {
                proto: "TCP6",
                local: format!("[{}]:{}", ipv6(&row.ucLocalAddr), u16::from_be(row.dwLocalPort as u16)),
                remote: format!("[{}]:{}", ipv6(&row.ucRemoteAddr), u16::from_be(row.dwRemotePort as u16)),
                state: "Established".into(),
                pid: row.dwOwningPid,
            });
        }
    }
}

fn udp_v4(out: &mut Vec<Endpoint>) {
    let Some(buf) = table(AF_INET.0 as u32, false, false) else {
        return;
    };
    unsafe {
        let count = *(buf.as_ptr() as *const u32);
        let rows = buf.as_ptr().add(4) as *const MIB_UDPROW_OWNER_PID;
        for i in 0..count as usize {
            let row = &*rows.add(i);
            out.push(Endpoint {
                proto: "UDP",
                local: format!("{}:{}", ipv4(row.dwLocalAddr), u16::from_be(row.dwLocalPort as u16)),
                remote: "*".into(),
                state: "Listen".into(),
                pid: row.dwOwningPid,
            });
        }
    }
}

fn udp_v6(out: &mut Vec<Endpoint>) {
    let Some(buf) = table(AF_INET6.0 as u32, false, true) else {
        return;
    };
    unsafe {
        let count = *(buf.as_ptr() as *const u32);
        let rows = buf.as_ptr().add(4) as *const MIB_UDP6ROW_OWNER_PID;
        for i in 0..count as usize {
            let row = &*rows.add(i);
            out.push(Endpoint {
                proto: "UDP6",
                local: format!("[{}]:{}", ipv6(&row.ucLocalAddr), u16::from_be(row.dwLocalPort as u16)),
                remote: "*".into(),
                state: "Listen".into(),
                pid: row.dwOwningPid,
            });
        }
    }
}

fn table(family: u32, tcp: bool, _v6: bool) -> Option<Vec<u8>> {
    unsafe {
        let mut size = 0u32;
        let first = if tcp {
            GetExtendedTcpTable(
                None,
                &mut size,
                false,
                family,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        } else {
            GetExtendedUdpTable(None, &mut size, false, family, UDP_TABLE_OWNER_PID, 0)
        };
        if size == 0 {
            let _ = first;
            return None;
        }
        let mut buf = vec![0u8; size as usize + 64];
        let err = if tcp {
            GetExtendedTcpTable(
                Some(buf.as_mut_ptr() as *mut _),
                &mut size,
                false,
                family,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        } else {
            GetExtendedUdpTable(
                Some(buf.as_mut_ptr() as *mut _),
                &mut size,
                false,
                family,
                UDP_TABLE_OWNER_PID,
                0,
            )
        };
        if err != 0 {
            return None;
        }
        Some(buf)
    }
}

fn ipv4(addr: u32) -> Ipv4Addr {
    Ipv4Addr::from(addr.to_le_bytes())
}

fn ipv6(bytes: &[u8; 16]) -> Ipv6Addr {
    Ipv6Addr::from(*bytes)
}
