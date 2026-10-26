//! "Check for updates", like the C build's update checker: asks GitHub for the
//! newest release of this port and compares versions. Uses WinHTTP, which is
//! part of Windows, so no HTTP library is bundled.

use std::ffi::c_void;

use windows::core::PCWSTR;
use windows::Win32::Networking::WinHttp::{
    WinHttpCloseHandle, WinHttpConnect, WinHttpOpen, WinHttpOpenRequest, WinHttpReadData, WinHttpReceiveResponse,
    WinHttpSendRequest, WinHttpSetTimeouts, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_FLAG_SECURE,
};

use crate::apps::wide;

/// The project page, for Help > Website and the About box.
pub const REPO_URL: &str = "https://github.com/NitroDiesel/firebreak";
pub const RELEASES_URL: &str = "https://github.com/NitroDiesel/firebreak/releases/latest";
const HOST: &str = "api.github.com";
const PATH: &str = "/repos/NitroDiesel/firebreak/releases/latest";

/// The newest release's version if it is newer than this build, None if this
/// build is current. Errors are for the "Check for updates" menu item.
pub fn newer_version() -> Result<Option<String>, String> {
    let body = get(HOST, PATH)?;
    let tag = json_string(&body, "tag_name").ok_or("The release information could not be read.")?;
    let latest = tag.trim_start_matches(['v', 'V', '.']).to_string();
    Ok(is_newer(&latest, crate::model::APP_VERSION).then_some(latest))
}

/// "3.10.0" is newer than "3.9.2".
fn is_newer(candidate: &str, current: &str) -> bool {
    let parts = |v: &str| -> Vec<u64> { v.split('.').map(|p| p.trim().parse().unwrap_or(0)).collect() };
    let (a, b) = (parts(candidate), parts(current));
    for i in 0..a.len().max(b.len()) {
        let (x, y) = (a.get(i).copied().unwrap_or(0), b.get(i).copied().unwrap_or(0));
        if x != y {
            return x > y;
        }
    }
    false
}

/// The value of `"key": "value"` in a JSON object, without a JSON library.
fn json_string(body: &str, key: &str) -> Option<String> {
    let start = body.find(&format!("\"{key}\""))?;
    let rest = &body[start + key.len() + 2..];
    let rest = rest.trim_start().strip_prefix(':')?.trim_start().strip_prefix('"')?;
    Some(rest[..rest.find('"')?].to_string())
}

struct Handle(*mut c_void);

impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                let _ = WinHttpCloseHandle(self.0);
            }
        }
    }
}

fn get(host: &str, path: &str) -> Result<String, String> {
    let fail = |what: &str| format!("Could not reach GitHub ({what}).");
    let agent = wide(&format!("Firebreak/{}", crate::model::APP_VERSION));
    let host = wide(host);
    let verb = wide("GET");
    let path = wide(path);
    let headers = wide("Accept: application/vnd.github+json\r\n");
    unsafe {
        let session = Handle(WinHttpOpen(
            PCWSTR(agent.as_ptr()),
            WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
            PCWSTR::null(),
            PCWSTR::null(),
            0,
        ));
        if session.0.is_null() {
            return Err(fail("session"));
        }
        let _ = WinHttpSetTimeouts(session.0, 5_000, 5_000, 5_000, 10_000);
        let connection = Handle(WinHttpConnect(session.0, PCWSTR(host.as_ptr()), 443, 0));
        if connection.0.is_null() {
            return Err(fail("connect"));
        }
        let request = Handle(WinHttpOpenRequest(
            connection.0,
            PCWSTR(verb.as_ptr()),
            PCWSTR(path.as_ptr()),
            PCWSTR::null(),
            PCWSTR::null(),
            std::ptr::null(),
            WINHTTP_FLAG_SECURE,
        ));
        if request.0.is_null() {
            return Err(fail("request"));
        }
        // Without the terminating zero.
        WinHttpSendRequest(request.0, Some(&headers[..headers.len() - 1]), None, 0, 0, 0).map_err(|_| fail("send"))?;
        WinHttpReceiveResponse(request.0, std::ptr::null_mut()).map_err(|_| fail("response"))?;
        let mut body = Vec::new();
        let mut chunk = vec![0u8; 16 * 1024];
        loop {
            let mut read = 0u32;
            WinHttpReadData(request.0, chunk.as_mut_ptr() as *mut c_void, chunk.len() as u32, &mut read)
                .map_err(|_| fail("read"))?;
            if read == 0 || body.len() > 4 << 20 {
                break;
            }
            body.extend_from_slice(&chunk[..read as usize]);
        }
        Ok(String::from_utf8_lossy(&body).into_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_compare_numerically() {
        assert!(is_newer("3.10.0", "3.9.2"));
        assert!(is_newer("3.9.3", "3.9.2"));
        assert!(!is_newer("3.9.2", "3.9.2"));
        assert!(!is_newer("3.9.1", "3.9.2"));
        assert!(is_newer("4", "3.9.2"));
    }

    /// Talks to GitHub; run with `cargo test -- --ignored`.
    #[test]
    #[ignore]
    fn asks_github() {
        let body = get(HOST, PATH).unwrap();
        let tag = json_string(&body, "tag_name").unwrap();
        assert!(tag.starts_with('v'), "{tag}");
        assert!(newer_version().is_ok());
    }

    #[test]
    fn reads_a_json_string() {
        let body = r#"{"url":"x","tag_name" : "v3.9.2","name":"simplewall 3.9.2"}"#;
        assert_eq!(json_string(body, "tag_name").as_deref(), Some("v3.9.2"));
        assert_eq!(json_string(body, "missing"), None);
    }
}
