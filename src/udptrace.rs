//! UDP traffic per socket (IsUdpTrafficEnabled), from a real-time ETW session
//! on the Microsoft-Windows-Kernel-Network provider. Its UDP send and receive
//! events carry the process id, the size, and both endpoints, so bytes can be
//! credited to the (process, local port) of a UDP row. Event metadata only;
//! no payload is read. The C build reads Winsock AFD events for the same
//! numbers (udpstats.c); the kernel network events are documented and simpler.
//! Needs administrator rights.

use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::{Arc, Mutex};

use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::System::Diagnostics::Etw::{
    CloseTrace, ControlTraceW, EnableTraceEx2, OpenTraceW, ProcessTrace, StartTraceW, CONTROLTRACE_HANDLE,
    EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_RECORD, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW,
    EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE, PROCESS_TRACE_MODE_EVENT_RECORD,
    PROCESS_TRACE_MODE_REAL_TIME, WNODE_FLAG_TRACED_GUID,
};

use crate::apps::wide;

const SESSION: &str = "Firebreak UDP traffic";
/// Microsoft-Windows-Kernel-Network.
const KERNEL_NETWORK: GUID = GUID::from_u128(0x7dd42a49_5329_4832_8dfd_43d979153a88);
/// KERNEL_NETWORK_KEYWORD_IPV4 | KERNEL_NETWORK_KEYWORD_IPV6.
const KEYWORDS: u64 = 0x10 | 0x20;
const TRACE_LEVEL_INFORMATION: u8 = 4;
/// UdpIp send and receive, IPv4 and IPv6.
const UDP_SEND_V4: u16 = 42;
const UDP_RECV_V4: u16 = 43;
const UDP_SEND_V6: u16 = 58;
const UDP_RECV_V6: u16 = 59;

/// (process id, local port) to (bytes received, bytes sent).
pub type Totals = HashMap<(u32, u16), (u64, u64)>;

pub struct UdpTrace {
    totals: Arc<Mutex<Totals>>,
}

impl UdpTrace {
    /// Start the session and its consumer thread.
    pub fn start() -> Result<Self, String> {
        if !crate::wfp::is_admin() {
            return Err("Administrator rights are required for UDP traffic statistics.".into());
        }
        stop_session();
        let name = wide(SESSION);
        let mut props = properties();
        let mut handle = CONTROLTRACE_HANDLE::default();
        unsafe {
            let status = StartTraceW(&mut handle, PCWSTR(name.as_ptr()), props.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES);
            if status != ERROR_SUCCESS {
                return Err(format!("Could not start the UDP traffic trace ({}).", status.0));
            }
            let status = EnableTraceEx2(
                handle,
                &KERNEL_NETWORK,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
                TRACE_LEVEL_INFORMATION,
                KEYWORDS,
                0,
                0,
                None,
            );
            if status != ERROR_SUCCESS {
                stop_session();
                return Err(format!("Could not enable the kernel network events ({}).", status.0));
            }
        }
        let totals = Arc::new(Mutex::new(Totals::new()));
        let sink = Box::into_raw(Box::new(totals.clone())) as usize;
        std::thread::spawn(move || unsafe {
            let mut name = wide(SESSION);
            let mut logfile = EVENT_TRACE_LOGFILEW {
                LoggerName: PWSTR(name.as_mut_ptr()),
                Context: sink as *mut c_void,
                ..Default::default()
            };
            logfile.Anonymous1.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
            logfile.Anonymous2.EventRecordCallback = Some(on_event);
            let trace = OpenTraceW(&mut logfile);
            if trace.Value != u64::MAX {
                // Returns when the session is stopped.
                let _ = ProcessTrace(&[trace], None, None);
                let _ = CloseTrace(trace);
            }
            drop(Box::from_raw(sink as *mut Arc<Mutex<Totals>>));
        });
        Ok(Self { totals })
    }

    pub fn totals(&self) -> Totals {
        self.totals.lock().unwrap().clone()
    }
}

impl Drop for UdpTrace {
    fn drop(&mut self) {
        stop_session();
    }
}

/// EVENT_TRACE_PROPERTIES followed by room for the session name.
fn properties() -> Vec<u8> {
    let size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + 1024;
    let mut buf = vec![0u8; size];
    let props = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
    unsafe {
        (*props).Wnode.BufferSize = size as u32;
        (*props).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        // Query performance counter time stamps.
        (*props).Wnode.ClientContext = 1;
        (*props).BufferSize = 64;
        (*props).MaximumBuffers = 64;
        (*props).FlushTimer = 1;
        (*props).LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        (*props).LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
    }
    buf
}

/// Stop the session, including one left behind by a previous run.
fn stop_session() {
    let name = wide(SESSION);
    let mut props = properties();
    unsafe {
        let _ = ControlTraceW(
            CONTROLTRACE_HANDLE::default(),
            PCWSTR(name.as_ptr()),
            props.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES,
            EVENT_TRACE_CONTROL_STOP,
        );
    }
}

unsafe extern "system" fn on_event(event: *mut EVENT_RECORD) {
    let Some(event) = event.as_ref() else {
        return;
    };
    if event.EventHeader.ProviderId != KERNEL_NETWORK || event.UserData.is_null() || event.UserContext.is_null() {
        return;
    }
    let data = std::slice::from_raw_parts(event.UserData as *const u8, event.UserDataLength as usize);
    let Some((pid, port, size, receive)) = parse(event.EventHeader.EventDescriptor.Id, data) else {
        return;
    };
    let totals = &*(event.UserContext as *const Arc<Mutex<Totals>>);
    if let Ok(mut totals) = totals.lock() {
        let entry = totals.entry((pid, port)).or_default();
        if receive {
            entry.0 += size as u64;
        } else {
            entry.1 += size as u64;
        }
    }
}

/// (process id, local port, size, received) from a UdpIp event. Layout:
/// PID, size, daddr, saddr, dport, sport; addresses are 4 or 16 bytes and
/// ports are in network order. On send the source is local; on receive, the
/// destination.
fn parse(id: u16, data: &[u8]) -> Option<(u32, u16, u32, bool)> {
    let (address, receive) = match id {
        UDP_SEND_V4 => (4, false),
        UDP_RECV_V4 => (4, true),
        UDP_SEND_V6 => (16, false),
        UDP_RECV_V6 => (16, true),
        _ => return None,
    };
    let u32_at = |at: usize| Some(u32::from_le_bytes(data.get(at..at + 4)?.try_into().ok()?));
    let port_at = |at: usize| Some(u16::from_be_bytes(data.get(at..at + 2)?.try_into().ok()?));
    let pid = u32_at(0)?;
    let size = u32_at(4)?;
    let ports = 8 + 2 * address;
    let (dport, sport) = (port_at(ports)?, port_at(ports + 2)?);
    Some((pid, if receive { dport } else { sport }, size, receive))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_udp_events_by_direction() {
        // PID 1234, 512 bytes, 1.2.3.4 -> 10.0.0.5, ports 53 and 50000 (network order).
        let mut v4 = Vec::new();
        v4.extend(1234u32.to_le_bytes());
        v4.extend(512u32.to_le_bytes());
        v4.extend([1, 2, 3, 4]);
        v4.extend([10, 0, 0, 5]);
        v4.extend(53u16.to_be_bytes());
        v4.extend(50000u16.to_be_bytes());
        assert_eq!(parse(UDP_SEND_V4, &v4), Some((1234, 50000, 512, false)));
        assert_eq!(parse(UDP_RECV_V4, &v4), Some((1234, 53, 512, true)));
        assert_eq!(parse(10, &v4), None);
        assert_eq!(parse(UDP_SEND_V6, &v4), None, "too short for IPv6");
    }
}
