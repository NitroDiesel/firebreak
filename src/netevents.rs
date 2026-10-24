//! Dropped-connection events from WFP: the live subscription behind
//! notifications and both packets logs, and the engine's stored history.
//! Port of `_wfp_logsubscribe` and `_wfp_logcallback` in log.c.

use std::collections::HashMap;
use std::ffi::c_void;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Mutex, OnceLock};

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{LocalFree, HANDLE, HLOCAL};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::*;
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::PSID;
use windows::Win32::Storage::FileSystem::QueryDosDeviceW;

use crate::apps::{utf16_prefix, wide};
use crate::model::{AppKind, SYSTEM_APP};
use crate::wfp::{is_admin, provider_guid, win, Engine, BLOCK_ALL_NAME, FILETIME_UNIX_EPOCH};

/// One dropped connection.
#[derive(Clone, Debug)]
pub struct Packet {
    /// Unix seconds.
    pub time: u64,
    /// DOS path, package SID, or "System", matching `AppItem::path`.
    pub path: String,
    pub kind: AppKind,
    pub protocol: u8,
    pub v6: bool,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub inbound: bool,
    pub loopback: bool,
    pub filter_id: u64,
    /// Name of the filter that dropped it.
    pub filter: String,
    /// Dropped by one of this program's filters.
    pub ours: bool,
    /// Dropped by the catch-all block filter: the app itself is not allowed.
    pub default_block: bool,
}

impl Packet {
    /// File name, package SID, or "System".
    pub fn name(&self) -> &str {
        match self.kind {
            AppKind::Regular => self.path.rsplit('\\').next().unwrap_or(&self.path),
            _ => &self.path,
        }
    }

    pub fn local(&self) -> String {
        endpoint(&self.local_addr, self.local_port, self.v6)
    }

    pub fn remote(&self) -> String {
        endpoint(&self.remote_addr, self.remote_port, self.v6)
    }

    pub fn direction(&self) -> &'static str {
        if self.loopback {
            "Loopback"
        } else if self.inbound {
            "Inbound"
        } else {
            "Outbound"
        }
    }
}

fn endpoint(addr: &str, port: u16, v6: bool) -> String {
    match (addr.is_empty(), port) {
        (true, _) => String::new(),
        (false, 0) => addr.to_string(),
        (false, _) if v6 => format!("[{addr}]:{port}"),
        (false, _) => format!("{addr}:{port}"),
    }
}

/// Filter and layer lookups, cached: a busy machine sends many events for few filters.
struct Lookup {
    engine: HANDLE,
    filters: HashMap<u64, (bool, String)>,
    layers: HashMap<u16, bool>,
}

// The engine handle may be used from the WFP callback threads.
unsafe impl Send for Lookup {}

impl Lookup {
    fn new(engine: HANDLE) -> Self {
        Self { engine, filters: HashMap::new(), layers: HashMap::new() }
    }

    /// (ours, name) for a filter id.
    unsafe fn filter(&mut self, id: u64) -> (bool, String) {
        if let Some(hit) = self.filters.get(&id) {
            return hit.clone();
        }
        let mut info = (false, String::new());
        let mut filter = std::ptr::null_mut();
        if FwpmFilterGetById0(self.engine, id, &mut filter) == 0 && !filter.is_null() {
            let provider = (*filter).providerKey;
            info.0 = !provider.is_null() && *provider == provider_guid();
            let name = (*filter).displayData.name;
            if !name.is_null() {
                info.1 = name.to_string().unwrap_or_default();
            }
            FwpmFreeMemory0(&mut filter as *mut _ as *mut *mut c_void);
        }
        self.filters.insert(id, info.clone());
        info
    }

    unsafe fn inbound(&mut self, layer_id: u16) -> bool {
        if let Some(hit) = self.layers.get(&layer_id) {
            return *hit;
        }
        let mut layer = std::ptr::null_mut();
        let mut inbound = false;
        if FwpmLayerGetById0(self.engine, layer_id, &mut layer) == 0 && !layer.is_null() {
            let key = (*layer).layerKey;
            inbound = key == FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4 || key == FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6;
            FwpmFreeMemory0(&mut layer as *mut _ as *mut *mut c_void);
        }
        self.layers.insert(layer_id, inbound);
        inbound
    }

    /// Convert a classify-drop event. None for other event types.
    unsafe fn packet(&mut self, event: &FWPM_NET_EVENT2) -> Option<Packet> {
        if event.r#type != FWPM_NET_EVENT_TYPE_CLASSIFY_DROP {
            return None;
        }
        let drop = event.Anonymous.classifyDrop;
        if drop.is_null() || (*drop).filterId == 0 {
            return None;
        }
        let (ours, filter) = self.filter((*drop).filterId);
        let inbound = self.inbound((*drop).layerId);
        Some(convert(&event.header, &*drop, inbound, ours, filter))
    }
}

unsafe fn convert(
    header: &FWPM_NET_EVENT_HEADER2,
    drop: &FWPM_NET_EVENT_CLASSIFY_DROP2,
    inbound: bool,
    ours: bool,
    filter: String,
) -> Packet {
    let has = |flag: u32| header.flags & flag != 0;
    let v6 = has(FWPM_NET_EVENT_FLAG_IP_VERSION_SET) && header.ipVersion == FWP_IP_VERSION_V6;
    let local_addr = if !has(FWPM_NET_EVENT_FLAG_LOCAL_ADDR_SET) {
        String::new()
    } else if v6 {
        Ipv6Addr::from(header.Anonymous1.localAddrV6.byteArray16).to_string()
    } else {
        Ipv4Addr::from(header.Anonymous1.localAddrV4).to_string()
    };
    let remote_addr = if !has(FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET) {
        String::new()
    } else if v6 {
        Ipv6Addr::from(header.Anonymous2.remoteAddrV6.byteArray16).to_string()
    } else {
        Ipv4Addr::from(header.Anonymous2.remoteAddrV4).to_string()
    };
    let package = if has(FWPM_NET_EVENT_FLAG_PACKAGE_ID_SET) && !header.packageSid.is_null() {
        sid_string(PSID(header.packageSid as *mut c_void)).filter(|sid| sid != "S-1-0-0")
    } else {
        None
    };
    let (path, kind) = if let Some(sid) = package {
        (sid, AppKind::Uwp)
    } else if has(FWPM_NET_EVENT_FLAG_APP_ID_SET) && !header.appId.data.is_null() {
        let raw = std::slice::from_raw_parts(header.appId.data as *const u16, header.appId.size as usize / 2);
        let nt = utf16_prefix(raw);
        if nt.eq_ignore_ascii_case(SYSTEM_APP) {
            (SYSTEM_APP.to_string(), AppKind::System)
        } else {
            (dos_path(&nt), AppKind::Regular)
        }
    } else {
        (SYSTEM_APP.to_string(), AppKind::System)
    };
    let stamp = (header.timeStamp.dwHighDateTime as u64) << 32 | header.timeStamp.dwLowDateTime as u64;
    Packet {
        time: stamp.saturating_sub(FILETIME_UNIX_EPOCH) / 10_000_000,
        path,
        kind,
        protocol: if has(FWPM_NET_EVENT_FLAG_IP_PROTOCOL_SET) { header.ipProtocol } else { 0 },
        v6,
        local_addr,
        local_port: if has(FWPM_NET_EVENT_FLAG_LOCAL_PORT_SET) { header.localPort } else { 0 },
        remote_addr,
        remote_port: if has(FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET) { header.remotePort } else { 0 },
        inbound,
        loopback: drop.isLoopback.as_bool(),
        filter_id: drop.filterId,
        default_block: ours && filter == BLOCK_ALL_NAME,
        filter,
        ours,
    }
}

unsafe fn sid_string(sid: PSID) -> Option<String> {
    let mut text = PWSTR::null();
    ConvertSidToStringSidW(sid, &mut text).ok()?;
    let out = text.to_string().ok();
    let _ = LocalFree(Some(HLOCAL(text.0 as *mut c_void)));
    out
}

/// `\device\harddiskvolume3\windows\notepad.exe` to `C:\windows\notepad.exe`,
/// like `_r_path_dospathfromnt`.
pub fn dos_path(nt: &str) -> String {
    static DEVICES: OnceLock<Mutex<Vec<(String, String)>>> = OnceLock::new();
    let lower = nt.to_ascii_lowercase();
    if let Some(rest) = lower.strip_prefix(r"\device\mup\") {
        return format!(r"\\{}", &nt[nt.len() - rest.len()..]);
    }
    let devices = DEVICES.get_or_init(|| Mutex::new(Vec::new()));
    for attempt in 0..2 {
        {
            let map = devices.lock().unwrap();
            for (device, drive) in map.iter() {
                if lower.starts_with(device.as_str())
                    && lower.as_bytes().get(device.len()).is_none_or(|b| *b == b'\\')
                {
                    return format!("{drive}{}", &nt[device.len()..]);
                }
            }
        }
        // A drive may have been mounted since; rebuild once.
        if attempt == 0 {
            *devices.lock().unwrap() = drive_devices();
        }
    }
    nt.to_string()
}

fn drive_devices() -> Vec<(String, String)> {
    let mut out = Vec::new();
    for letter in b'A'..=b'Z' {
        let drive = format!("{}:", letter as char);
        let name = wide(&drive);
        let mut buf = [0u16; 512];
        if unsafe { QueryDosDeviceW(PCWSTR(name.as_ptr()), Some(&mut buf)) } > 0 {
            out.push((utf16_prefix(&buf).to_ascii_lowercase(), drive));
        }
    }
    out
}

/// Stored drops caused by this provider's filters, newest first.
pub fn history(limit: usize) -> Result<Vec<Packet>, String> {
    if !is_admin() {
        return Err("Administrator rights are required to read the packets log.".into());
    }
    let engine = Engine::open()?;
    let mut lookup = Lookup::new(engine.handle);
    let mut out = Vec::new();
    unsafe {
        let mut handle = HANDLE::default();
        win(FwpmNetEventCreateEnumHandle0(engine.handle, None, &mut handle), "net event enum")?;
        loop {
            let mut entries: *mut *mut FWPM_NET_EVENT2 = std::ptr::null_mut();
            let mut returned = 0u32;
            if FwpmNetEventEnum2(engine.handle, handle, 512, &mut entries, &mut returned) != 0
                || returned == 0
                || entries.is_null()
            {
                break;
            }
            for i in 0..returned as usize {
                let event = *entries.add(i);
                if let Some(packet) = event.as_ref().and_then(|e| lookup.packet(e)) {
                    if packet.ours {
                        out.push(packet);
                    }
                }
            }
            FwpmFreeMemory0(&mut entries as *mut _ as *mut *mut c_void);
        }
        let _ = FwpmNetEventDestroyEnumHandle0(engine.handle, handle);
    }
    out.sort_by(|a, b| b.time.cmp(&a.time));
    out.truncate(limit);
    Ok(out)
}

type Sink = Box<dyn Fn(Packet) + Send + Sync>;

struct Context {
    lookup: Mutex<Lookup>,
    sink: Sink,
}

/// A live subscription. Dropping it unsubscribes.
pub struct Subscription {
    engine: Engine,
    handle: HANDLE,
    context: *mut Context,
}

unsafe impl Send for Subscription {}

/// Call `sink` for every dropped connection, from WFP's own threads.
pub fn subscribe(sink: impl Fn(Packet) + Send + Sync + 'static) -> Result<Subscription, String> {
    if !is_admin() {
        return Err("Administrator rights are required for notifications and the packets log.".into());
    }
    let engine = Engine::open()?;
    let context = Box::into_raw(Box::new(Context {
        lookup: Mutex::new(Lookup::new(engine.handle)),
        sink: Box::new(sink),
    }));
    let mut template = FWPM_NET_EVENT_ENUM_TEMPLATE0::default();
    let subscription = FWPM_NET_EVENT_SUBSCRIPTION0 {
        enumTemplate: &mut template,
        ..Default::default()
    };
    let mut handle = HANDLE::default();
    let status = unsafe {
        FwpmNetEventSubscribe1(engine.handle, &subscription, Some(callback), Some(context as *const c_void), &mut handle)
    };
    if let Err(err) = win(status, "FwpmNetEventSubscribe1") {
        drop(unsafe { Box::from_raw(context) });
        return Err(err);
    }
    Ok(Subscription { engine, handle, context })
}

impl Drop for Subscription {
    fn drop(&mut self) {
        unsafe {
            // Returns once no callback is running, so the context can go.
            let _ = FwpmNetEventUnsubscribe0(self.engine.handle, self.handle);
            drop(Box::from_raw(self.context));
        }
    }
}

unsafe extern "system" fn callback(context: *mut c_void, event: *const FWPM_NET_EVENT2) {
    let (Some(context), Some(event)) = ((context as *const Context).as_ref(), event.as_ref()) else {
        return;
    };
    let packet = match context.lookup.lock() {
        Ok(mut lookup) => lookup.packet(event),
        Err(_) => None,
    };
    if let Some(packet) = packet {
        (context.sink)(packet);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nt_paths_become_dos_paths() {
        let system = std::env::var("SystemRoot").unwrap();
        let drive = &system[..2];
        let device = drive_devices()
            .into_iter()
            .find(|(_, d)| d.eq_ignore_ascii_case(drive))
            .map(|(device, _)| device)
            .unwrap();
        let nt = format!(r"{device}\windows\system32\svchost.exe");
        assert!(dos_path(&nt).eq_ignore_ascii_case(&format!(r"{drive}\windows\system32\svchost.exe")));
        assert_eq!(dos_path(r"\device\mup\server\share\a.exe"), r"\\server\share\a.exe");
        assert_eq!(dos_path("System"), "System");
    }

    #[test]
    fn endpoints_bracket_ipv6_only() {
        assert_eq!(endpoint("10.0.0.1", 80, false), "10.0.0.1:80");
        assert_eq!(endpoint("::1", 80, true), "[::1]:80");
        assert_eq!(endpoint("10.0.0.1", 0, false), "10.0.0.1");
        assert_eq!(endpoint("", 80, false), "");
    }
}
