//! Running processes, Win32 services, and UWP packages. This is the inventory
//! the Apps, Services, and UWP apps tabs edit.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::path::Path;

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, ERROR_SUCCESS, MAX_PATH};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Registry::{
    RegCloseKey, RegEnumKeyExW, RegGetValueW, RegOpenKeyExW, HKEY, HKEY_CURRENT_USER, KEY_READ,
    RRF_RT_REG_SZ,
};
use windows::Win32::System::Services::{
    CloseServiceHandle, EnumServicesStatusExW, OpenSCManagerW, OpenServiceW, QueryServiceConfigW,
    ENUM_SERVICE_STATUS_PROCESSW, QUERY_SERVICE_CONFIGW, SC_ENUM_PROCESS_INFO,
    SC_MANAGER_ENUMERATE_SERVICE, SERVICE_QUERY_CONFIG, SERVICE_STATE_ALL, SERVICE_WIN32,
};
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, TerminateProcess, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
};
use windows::Win32::UI::Shell::SHLoadIndirectString;

use crate::model::{AppItem, AppKind, SYSTEM_APP};

/// Per-user service instances (`CDPUserSvc_1a2b3`) get a new name at every
/// logon, so listing them only piles up stale entries (henrypp/simplewall#2123).
const SERVICE_USERSERVICE_INSTANCE: u32 = 0x80;

const MAPPINGS: &str =
    r"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Mappings";

pub fn enumerate() -> Vec<AppItem> {
    let mut map: BTreeMap<String, AppItem> = BTreeMap::new();
    let system = AppItem {
        enabled: true,
        ..AppItem::new(SYSTEM_APP.into(), SYSTEM_APP.into(), AppKind::System)
    };
    for app in std::iter::once(system)
        .chain(processes())
        .chain(services())
        .chain(packages())
    {
        map.entry(key(&app)).or_insert(app);
    }
    sorted(map)
}

/// Keep saved allow/timer/comment when an app is still present, and keep saved
/// apps that are not running so rules survive a reboot. A saved service that is
/// gone and was never configured is dropped, which also clears out old per-user
/// service instances.
pub fn merge(saved: &[AppItem], live: Vec<AppItem>) -> Vec<AppItem> {
    let mut map: BTreeMap<String, AppItem> = BTreeMap::new();
    let live_services: std::collections::HashSet<String> =
        live.iter().filter(|a| a.kind == AppKind::Service).map(key).collect();
    for app in saved {
        let untouched = !app.enabled && !app.pinned && !app.has_timer() && app.comment.is_empty();
        if app.kind == AppKind::Service && untouched && !live_services.is_empty() && !live_services.contains(&key(app)) {
            continue;
        }
        map.insert(key(app), app.clone());
    }
    for app in live {
        let key = key(&app);
        let next = match map.get(&key) {
            Some(prev) => AppItem {
                enabled: prev.enabled,
                timer_until: prev.timer_until,
                comment: prev.comment.clone(),
                pinned: prev.pinned,
                silent: prev.silent,
                hash: prev.hash.clone(),
                last_notify: prev.last_notify,
                added: if prev.added == 0 { app.added } else { prev.added },
                ..app
            },
            None => app,
        };
        map.insert(key, next);
    }
    sorted(map)
}

fn key(app: &AppItem) -> String {
    let kind = match app.kind {
        AppKind::Service => "svc:",
        AppKind::Uwp => "uwp:",
        _ => "",
    };
    format!("{kind}{}", app.path.to_lowercase())
}

fn sorted(map: BTreeMap<String, AppItem>) -> Vec<AppItem> {
    let mut apps: Vec<_> = map.into_values().collect();
    apps.sort_by_cached_key(|app| app.display_name.to_lowercase());
    apps
}

/// Image path behind a service name, for "Open containing folder".
pub fn resolve_service_image(name: &str) -> Option<String> {
    unsafe {
        let scm = OpenSCManagerW(None, None, SC_MANAGER_ENUMERATE_SERVICE).ok()?;
        let wide = wide(name);
        let path = match OpenServiceW(scm, PCWSTR(wide.as_ptr()), SERVICE_QUERY_CONFIG) {
            Ok(svc) => {
                let path = query_service_path(svc);
                let _ = CloseServiceHandle(svc);
                path
            }
            Err(_) => None,
        };
        let _ = CloseServiceHandle(scm);
        path
    }
}

/// Process id to executable name, for the Connections tab.
pub fn process_names() -> BTreeMap<u32, String> {
    let mut out = BTreeMap::new();
    walk_processes(|pid, exe| {
        out.insert(pid, exe.to_string());
    });
    out
}

/// End every process running from `path`, like the notification's "Kill process"
/// (`_app_notify_killprocess`). Returns how many were ended.
pub fn kill_processes(path: &str) -> usize {
    let mut pids = Vec::new();
    walk_processes(|pid, _| {
        if process_path(pid).is_some_and(|p| p.eq_ignore_ascii_case(path)) {
            pids.push(pid);
        }
    });
    pids.into_iter()
        .filter(|pid| unsafe {
            match OpenProcess(PROCESS_TERMINATE, false, *pid) {
                Ok(handle) => {
                    let ok = TerminateProcess(handle, 1).is_ok();
                    let _ = CloseHandle(handle);
                    ok
                }
                Err(_) => false,
            }
        })
        .count()
}

fn walk_processes(mut visit: impl FnMut(u32, &str)) {
    unsafe {
        let Ok(snap) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else {
            return;
        };
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        if Process32FirstW(snap, &mut entry).is_ok() {
            loop {
                visit(entry.th32ProcessID, &utf16_prefix(&entry.szExeFile));
                if Process32NextW(snap, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snap);
    }
}

/// Running programs, for the app monitor.
pub fn processes() -> Vec<AppItem> {
    let mut out = Vec::new();
    walk_processes(|pid, exe| {
        if let Some(path) = process_path(pid) {
            let name = Path::new(&path)
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| exe.to_string());
            out.push(AppItem::new(path, name, AppKind::Regular));
        }
    });
    out
}

pub fn process_path(pid: u32) -> Option<String> {
    if pid == 0 {
        return None;
    }
    unsafe {
        let proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut buf = vec![0u16; MAX_PATH as usize * 4];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(proc, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut len);
        let _ = CloseHandle(proc);
        if ok.is_err() || len == 0 {
            return None;
        }
        Some(OsString::from_wide(&buf[..len as usize]).to_string_lossy().into_owned())
    }
}

/// One entry per service, keyed by service name. Services that share
/// svchost.exe are told apart by their service SID, as in the C build.
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
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            None,
            &mut needed,
            &mut count,
            Some(&mut resume),
            None,
        );
        if needed != 0 {
            let mut buf = vec![0u8; needed as usize];
            resume = 0;
            if EnumServicesStatusExW(
                scm,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32,
                SERVICE_STATE_ALL,
                Some(&mut buf),
                &mut needed,
                &mut count,
                Some(&mut resume),
                None,
            )
            .is_ok()
            {
                let entries = std::slice::from_raw_parts(
                    buf.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW,
                    count as usize,
                );
                for entry in entries {
                    if entry.ServiceStatusProcess.dwServiceType.0 & SERVICE_USERSERVICE_INSTANCE != 0 {
                        continue;
                    }
                    let name = pwstr_to_string(entry.lpServiceName);
                    let display = pwstr_to_string(entry.lpDisplayName);
                    if !name.is_empty() {
                        let display = if display.is_empty() { name.clone() } else { display };
                        out.push(AppItem::new(name, display, AppKind::Service));
                    }
                }
            }
        }
        let _ = CloseServiceHandle(scm);
    }
    out
}

/// UWP packages from the AppContainer mapping list, keyed by package SID.
fn packages() -> Vec<AppItem> {
    let mut out = Vec::new();
    unsafe {
        let mut root = HKEY::default();
        let path = wide(MAPPINGS);
        if RegOpenKeyExW(HKEY_CURRENT_USER, PCWSTR(path.as_ptr()), None, KEY_READ, &mut root)
            != ERROR_SUCCESS
        {
            return out;
        }
        let mut index = 0;
        loop {
            let mut name = [0u16; 256];
            let mut len = name.len() as u32;
            if RegEnumKeyExW(root, index, Some(PWSTR(name.as_mut_ptr())), &mut len, None, None, None, None)
                != ERROR_SUCCESS
            {
                break;
            }
            index += 1;
            let sid = String::from_utf16_lossy(&name[..len as usize]);
            let display = reg_string(root, &sid, "DisplayName")
                .map(|text| indirect_string(&text))
                .filter(|text| !text.is_empty() && !text.starts_with("@{"))
                .or_else(|| reg_string(root, &sid, "Moniker"))
                .unwrap_or_else(|| sid.clone());
            out.push(AppItem::new(sid, display, AppKind::Uwp));
        }
        let _ = RegCloseKey(root);
    }
    out
}

unsafe fn reg_string(root: HKEY, subkey: &str, value: &str) -> Option<String> {
    let subkey = wide(subkey);
    let value = wide(value);
    let mut buf = vec![0u16; 1024];
    let mut size = (buf.len() * 2) as u32;
    let status = RegGetValueW(
        root,
        PCWSTR(subkey.as_ptr()),
        PCWSTR(value.as_ptr()),
        RRF_RT_REG_SZ,
        None,
        Some(buf.as_mut_ptr() as *mut _),
        Some(&mut size),
    );
    (status == ERROR_SUCCESS).then(|| utf16_prefix(&buf))
}

/// Resolves `@{Package?ms-resource://...}` display names.
fn indirect_string(text: &str) -> String {
    if !text.starts_with('@') {
        return text.to_string();
    }
    let source = wide(text);
    let mut out = [0u16; 512];
    match unsafe { SHLoadIndirectString(PCWSTR(source.as_ptr()), &mut out, None) } {
        Ok(()) => utf16_prefix(&out),
        Err(_) => text.to_string(),
    }
}

fn query_service_path(svc: windows::Win32::System::Services::SC_HANDLE) -> Option<String> {
    unsafe {
        let mut needed = 0u32;
        let _ = QueryServiceConfigW(svc, None, 0, &mut needed);
        if needed == 0 {
            return None;
        }
        let mut buf = vec![0u8; needed as usize];
        let cfg = buf.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW;
        QueryServiceConfigW(svc, Some(cfg), needed, &mut needed).ok()?;
        Some(clean_service_binary(&pwstr_to_string((*cfg).lpBinaryPathName)))
    }
}

fn clean_service_binary(raw: &str) -> String {
    let s = raw.trim();
    let s = s.strip_prefix("\\??\\").unwrap_or(s);
    let path = if let Some(rest) = s.strip_prefix('"') {
        rest.split('"').next().unwrap_or(rest).to_string()
    } else {
        s.split_whitespace().next().unwrap_or(s).to_string()
    };
    expand_env(&path)
}

/// Expands `%SystemRoot%`-style variables, case-insensitively.
pub fn expand_env(path: &str) -> String {
    let mut out = String::new();
    let mut rest = path;
    while let Some(start) = rest.find('%') {
        let Some(len) = rest[start + 1..].find('%') else {
            break;
        };
        let name = &rest[start + 1..start + 1 + len];
        out.push_str(&rest[..start]);
        match std::env::var(name) {
            Ok(value) => out.push_str(&value),
            Err(_) => out.push_str(&rest[start..start + len + 2]),
        }
        rest = &rest[start + len + 2..];
    }
    out.push_str(rest);
    out
}

pub fn wide(s: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn pwstr_to_string(p: PWSTR) -> String {
    if p.0.is_null() {
        return String::new();
    }
    unsafe { p.to_string().unwrap_or_default() }
}

pub fn utf16_prefix(buf: &[u16]) -> String {
    let end = buf.iter().position(|c| *c == 0).unwrap_or(buf.len());
    OsString::from_wide(&buf[..end]).to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_environment_case_insensitively() {
        let root = std::env::var("SystemRoot").unwrap();
        assert_eq!(expand_env(r"%systemroot%\x.exe"), format!(r"{root}\x.exe"));
        assert_eq!(expand_env(r"%NOPE_NOT_SET%\x"), r"%NOPE_NOT_SET%\x");
    }

    #[test]
    fn merge_keeps_user_state() {
        let mut saved = AppItem::new(r"C:\a.exe".into(), "a.exe".into(), AppKind::Regular);
        saved.enabled = true;
        saved.added = 5;
        let live = vec![AppItem::new(r"c:\A.exe".into(), "a.exe".into(), AppKind::Regular)];
        let merged = merge(&[saved], live);
        assert_eq!(merged.len(), 1);
        assert!(merged[0].enabled);
        assert_eq!(merged[0].added, 5);
    }

    #[test]
    fn merge_drops_gone_services_nobody_configured() {
        let stale = AppItem::new("CDPUserSvc_580ac".into(), "CDP".into(), AppKind::Service);
        let mut allowed = AppItem::new("OldSvc".into(), "Old".into(), AppKind::Service);
        allowed.enabled = true;
        let live = vec![AppItem::new("Dnscache".into(), "DNS Client".into(), AppKind::Service)];
        let merged = merge(&[stale, allowed], live);
        let names: Vec<&str> = merged.iter().map(|a| a.path.as_str()).collect();
        assert_eq!(names, ["Dnscache", "OldSvc"]);
    }
}
