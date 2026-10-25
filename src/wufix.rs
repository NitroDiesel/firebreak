//! "Allow Windows Update" (IsWUFixEnabled), `_app_wufixenable` in helper.c.
//! The update services share svchost.exe with everything else, so the C build
//! points them at a hardlink of svchost named wusvc.exe, which can then be
//! allowed on its own. Turning it off points them back at svchost.exe.
//! Services are stopped when their image changes; Windows restarts them on demand.

use std::path::PathBuf;

use windows::core::PCWSTR;
use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::Storage::FileSystem::CreateHardLinkW;
use windows::Win32::System::Registry::{
    RegCloseKey, RegGetValueW, RegOpenKeyExW, RegSetValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE,
    REG_EXPAND_SZ, RRF_NOEXPAND, RRF_RT_REG_EXPAND_SZ, RRF_RT_REG_SZ,
};
use windows::Win32::System::Services::{
    CloseServiceHandle, ControlService, OpenSCManagerW, OpenServiceW, QueryServiceStatus, SC_MANAGER_CONNECT,
    SERVICE_CONTROL_STOP, SERVICE_QUERY_STATUS, SERVICE_STATUS, SERVICE_STOP, SERVICE_STOPPED, SERVICE_STOP_PENDING,
};

use crate::apps::{utf16_prefix, wide};

/// Service name and its svchost group, as in the C build.
const SERVICES: [(&str, &str); 3] = [("wuauserv", "netsvcs"), ("DoSvc", "NetworkService"), ("UsoSvc", "netsvcs")];

fn system32() -> PathBuf {
    PathBuf::from(std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into())).join("System32")
}

/// Path of the update services' own svchost copy.
pub fn wusvc_path() -> PathBuf {
    system32().join("wusvc.exe")
}

/// Point the update services at wusvc.exe (`on`) or back at svchost.exe.
pub fn set(on: bool) -> Result<(), String> {
    if !crate::wfp::is_admin() {
        return Err("Administrator rights are required to change Windows Update services.".into());
    }
    let wusvc = wusvc_path();
    if on {
        let _ = std::fs::remove_file(&wusvc);
        let link = wide(&wusvc.to_string_lossy());
        let target = wide(&system32().join("svchost.exe").to_string_lossy());
        let linked = unsafe { CreateHardLinkW(PCWSTR(link.as_ptr()), PCWSTR(target.as_ptr()), None) }.is_ok();
        if !linked {
            std::fs::copy(system32().join("svchost.exe"), &wusvc).map_err(|e| format!("Could not create wusvc.exe: {e}"))?;
        }
    }
    let image = if on { r"\wusvc.exe" } else { r"\svchost.exe" };
    let mut errors = Vec::new();
    for (service, group) in SERVICES {
        if let Err(err) = point_service(service, &format!(r"%systemroot%\system32{image} -k {group} -p"), on) {
            errors.push(format!("{service}: {err}"));
        }
    }
    if !on {
        // In use until the services have stopped; a leftover file is harmless.
        let _ = std::fs::remove_file(&wusvc);
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

fn point_service(service: &str, image_path: &str, on: bool) -> Result<(), String> {
    let key_path = wide(&format!(r"SYSTEM\CurrentControlSet\Services\{service}"));
    let name = wide("ImagePath");
    unsafe {
        let mut key = HKEY::default();
        let status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, PCWSTR(key_path.as_ptr()), None, KEY_READ | KEY_WRITE, &mut key);
        if status != ERROR_SUCCESS {
            return Err(format!("registry key not opened ({})", status.0));
        }
        let mut current = vec![0u16; 1024];
        let mut size = (current.len() * 2) as u32;
        let read = RegGetValueW(
            key,
            None,
            PCWSTR(name.as_ptr()),
            RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND,
            None,
            Some(current.as_mut_ptr() as *mut _),
            Some(&mut size),
        );
        let current = if read == ERROR_SUCCESS { utf16_prefix(&current).to_lowercase() } else { String::new() };
        let value = wide(image_path);
        let bytes = std::slice::from_raw_parts(value.as_ptr() as *const u8, value.len() * 2);
        let status = RegSetValueExW(key, PCWSTR(name.as_ptr()), None, REG_EXPAND_SZ, Some(bytes));
        let _ = RegCloseKey(key);
        if status != ERROR_SUCCESS {
            return Err(format!("ImagePath not written ({})", status.0));
        }
        let was_on = current.contains(r"\wusvc.exe");
        if was_on != on {
            stop(service);
        }
    }
    Ok(())
}

/// Stop a running service so it restarts from its new image.
fn stop(service: &str) {
    let name = wide(service);
    unsafe {
        let Ok(manager) = OpenSCManagerW(None, None, SC_MANAGER_CONNECT) else {
            return;
        };
        if let Ok(handle) = OpenServiceW(manager, PCWSTR(name.as_ptr()), SERVICE_STOP | SERVICE_QUERY_STATUS) {
            let mut status = SERVICE_STATUS::default();
            if QueryServiceStatus(handle, &mut status).is_ok()
                && status.dwCurrentState != SERVICE_STOPPED
                && status.dwCurrentState != SERVICE_STOP_PENDING
            {
                let _ = ControlService(handle, SERVICE_CONTROL_STOP, &mut status);
            }
            let _ = CloseServiceHandle(handle);
        }
        let _ = CloseServiceHandle(manager);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image_path(service: &str) -> String {
        let output = std::process::Command::new("reg.exe")
            .args(["query", &format!(r"HKLM\SYSTEM\CurrentControlSet\Services\{service}"), "/v", "ImagePath"])
            .output()
            .unwrap();
        String::from_utf8_lossy(&output.stdout).to_lowercase()
    }

    /// Turns the fix on and off again on this machine. Needs an elevated
    /// console: `cargo test wufix -- --ignored`.
    #[test]
    #[ignore]
    fn points_services_there_and_back() {
        set(true).unwrap();
        assert!(wusvc_path().exists());
        for (service, group) in SERVICES {
            assert!(image_path(service).contains(&format!(r"\wusvc.exe -k {} -p", group.to_lowercase())));
        }
        set(false).unwrap();
        for (service, group) in SERVICES {
            assert!(image_path(service).contains(&format!(r"\svchost.exe -k {} -p", group.to_lowercase())));
        }
    }
}
