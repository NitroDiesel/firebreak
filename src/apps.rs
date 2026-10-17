//! Running processes and Win32 services. This is the inventory the Apps tab edits.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::path::Path;

use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, MAX_PATH};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Services::{
    EnumServicesStatusExW, OpenSCManagerW, OpenServiceW, QueryServiceConfigW, SC_HANDLE,
    SC_MANAGER_ENUMERATE_SERVICE, SERVICE_QUERY_CONFIG, SERVICE_STATE_ALL, SERVICE_WIN32,
    ENUM_SERVICE_STATUS_PROCESSW, QUERY_SERVICE_CONFIGW,
};
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
};

use crate::model::{AppItem, AppKind};

pub fn enumerate() -> Vec<AppItem> {
    let mut map: BTreeMap<String, AppItem> = BTreeMap::new();
    for app in processes() {
        map.entry(app.path.to_ascii_lowercase()).or_insert(app);
    }
    for app in services() {
        map.entry(app.path.to_ascii_lowercase()).or_insert(app);
    }
    if let Some(system) = system_image() {
        map.entry(system.path.to_ascii_lowercase()).or_insert(system);
    }
    let mut apps: Vec<_> = map.into_values().collect();
    apps.sort_by(|a, b| a.display_name.to_lowercase().cmp(&b.display_name.to_lowercase()));
    apps
}

/// Keep saved allow/timer/comment when a path is still present, and keep saved
/// apps that are not running so rules survive a reboot.
pub fn merge(saved: &[AppItem], live: Vec<AppItem>) -> Vec<AppItem> {
    let mut map: BTreeMap<String, AppItem> = BTreeMap::new();
    for app in saved {
        map.insert(app.path.to_ascii_lowercase(), app.clone());
    }
    for app in live {
        let key = app.path.to_ascii_lowercase();
        if let Some(prev) = map.get(&key) {
            let mut next = app;
            next.enabled = prev.enabled;
            next.timer_until = prev.timer_until;
            next.comment = prev.comment.clone();
            next.pinned = prev.pinned;
            map.insert(key, next);
        } else {
            map.insert(key, app);
        }
    }
    let mut apps: Vec<_> = map.into_values().collect();
    apps.sort_by(|a, b| a.display_name.to_lowercase().cmp(&b.display_name.to_lowercase()));
    apps
}

pub fn resolve_service_image(name: &str) -> Option<String> {
    unsafe {
        let scm = OpenSCManagerW(None, None, SC_MANAGER_ENUMERATE_SERVICE).ok()?;
        let wide = wide(name);
        let svc = OpenServiceW(scm, windows::core::PCWSTR(wide.as_ptr()), SERVICE_QUERY_CONFIG).ok()?;
        let path = query_service_path(svc);
        let _ = windows::Win32::System::Services::CloseServiceHandle(svc);
        let _ = windows::Win32::System::Services::CloseServiceHandle(scm);
        path
    }
}

fn processes() -> Vec<AppItem> {
    let mut out = Vec::new();
    unsafe {
        let Ok(snap) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else {
            return out;
        };
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        if Process32FirstW(snap, &mut entry).is_ok() {
            loop {
                let pid = entry.th32ProcessID;
                if let Some(path) = process_path(pid) {
                    let name = Path::new(&path)
                        .file_name()
                        .map(|s| s.to_string_lossy().into_owned())
                        .unwrap_or_else(|| utf16_prefix(&entry.szExeFile));
                    out.push(AppItem {
                        path,
                        display_name: name,
                        kind: AppKind::Regular,
                        enabled: false,
                        timer_until: 0,
                        comment: String::new(),
                        pinned: false,
                    });
                }
                if Process32NextW(snap, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snap);
    }
    out
}

fn process_path(pid: u32) -> Option<String> {
    if pid == 0 {
        return None;
    }
    unsafe {
        let Ok(proc) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) else {
            return None;
        };
        let mut buf = vec![0u16; MAX_PATH as usize * 4];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(
            proc,
            PROCESS_NAME_WIN32,
            PWSTR(buf.as_mut_ptr()),
            &mut len,
        );
        let _ = CloseHandle(proc);
        if ok.is_err() || len == 0 {
            return None;
        }
        Some(OsString::from_wide(&buf[..len as usize]).to_string_lossy().into_owned())
    }
}

fn services() -> Vec<AppItem> {
    let mut out = Vec::new();
    unsafe {
        let Ok(scm) = OpenSCManagerW(None, None, SC_MANAGER_ENUMERATE_SERVICE) else {
            return out;
        };
        let mut needed = 0u32;
        let mut count = 0u32;
        let mut resume = 0u32;
        let _ = EnumServicesStatusExW(
            scm,
            windows::Win32::System::Services::SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            None,
            &mut needed,
            &mut count,
            Some(&mut resume),
            None,
        );
        if needed == 0 {
            let _ = windows::Win32::System::Services::CloseServiceHandle(scm);
            return out;
        }
        let mut buf = vec![0u8; needed as usize];
        resume = 0;
        if EnumServicesStatusExW(
            scm,
            windows::Win32::System::Services::SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            Some(&mut buf),
            &mut needed,
            &mut count,
            Some(&mut resume),
            None,
        )
        .is_err()
        {
            let _ = windows::Win32::System::Services::CloseServiceHandle(scm);
            return out;
        }
        let entries = std::slice::from_raw_parts(
            buf.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW,
            count as usize,
        );
        for entry in entries {
            let name = pwstr_to_string(entry.lpServiceName);
            if let Some(path) = service_path(scm, &name) {
                let display = Path::new(&path)
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or(name);
                out.push(AppItem {
                    path,
                    display_name: display,
                    kind: AppKind::Service,
                    enabled: false,
                    timer_until: 0,
                    comment: String::new(),
                    pinned: false,
                });
            }
        }
        let _ = windows::Win32::System::Services::CloseServiceHandle(scm);
    }
    out
}

fn service_path(scm: SC_HANDLE, name: &str) -> Option<String> {
    unsafe {
        let wide = wide(name);
        let svc = OpenServiceW(scm, windows::core::PCWSTR(wide.as_ptr()), SERVICE_QUERY_CONFIG).ok()?;
        let path = query_service_path(svc);
        let _ = windows::Win32::System::Services::CloseServiceHandle(svc);
        path
    }
}

fn query_service_path(svc: SC_HANDLE) -> Option<String> {
    unsafe {
        let mut needed = 0u32;
        let _ = QueryServiceConfigW(svc, None, 0, &mut needed);
        if needed == 0 {
            return None;
        }
        let mut buf = vec![0u8; needed as usize];
        let cfg = buf.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW;
        if QueryServiceConfigW(svc, Some(cfg), needed, &mut needed).is_err() {
            return None;
        }
        let raw = pwstr_to_string((*cfg).lpBinaryPathName);
        Some(clean_service_binary(&raw))
    }
}

fn clean_service_binary(raw: &str) -> String {
    let s = raw.trim();
    let s = s.strip_prefix("\\??\\").unwrap_or(s);
    if let Some(rest) = s.strip_prefix('"') {
        rest.split('"').next().unwrap_or(rest).to_string()
    } else {
        s.split_whitespace().next().unwrap_or(s).to_string()
    }
}

fn system_image() -> Option<AppItem> {
    let root = std::env::var("SYSTEMROOT").ok()?;
    let path = Path::new(&root).join("System32").join("ntoskrnl.exe");
    Some(AppItem {
        display_name: "System".into(),
        path: path.to_string_lossy().into_owned(),
        kind: AppKind::System,
        enabled: true,
        timer_until: 0,
        comment: String::new(),
        pinned: false,
    })
}

fn wide(s: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn pwstr_to_string(p: windows::core::PWSTR) -> String {
    if p.0.is_null() {
        return String::new();
    }
    unsafe {
        let mut len = 0usize;
        while *p.0.add(len) != 0 {
            len += 1;
        }
        OsString::from_wide(std::slice::from_raw_parts(p.0, len))
            .to_string_lossy()
            .into_owned()
    }
}

fn utf16_prefix(buf: &[u16]) -> String {
    let end = buf.iter().position(|c| *c == 0).unwrap_or(buf.len());
    OsString::from_wide(&buf[..end]).to_string_lossy().into_owned()
}
