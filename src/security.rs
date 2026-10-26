//! Who signed a file, and its SHA-256, like `_app_verifyfromfile`,
//! `_app_verifyfilefromcatalog`, and `_r_crypt_getfilehash` in the C build.
//! Most Windows files are signed through a catalog rather than embedded
//! signatures, so both are checked.

use std::ffi::c_void;
use std::os::windows::io::AsRawHandle;

use windows::core::{GUID, PCWSTR};
use windows::Win32::Foundation::{HANDLE, HWND};
use windows::Win32::Security::Cryptography::Catalog::{
    CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2, CryptCATAdminEnumCatalogFromHash,
    CryptCATAdminReleaseCatalogContext, CryptCATAdminReleaseContext, CryptCATCatalogInfoFromContext, CATALOG_INFO,
};
use windows::Win32::Security::Cryptography::{CertGetNameStringW, CERT_NAME_ATTR_TYPE};
use windows::Win32::Security::WinTrust::{
    WTHelperGetProvCertFromChain, WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData, WinVerifyTrust,
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_CATALOG_INFO, WINTRUST_DATA, WINTRUST_FILE_INFO,
    WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_CATALOG, WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_REVOKE_WHOLECHAIN,
    WTD_SAFER_FLAG, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
};

use crate::apps::wide;

/// The signer's common name, or None when the file is not validly signed.
/// `revocation` checks certificate revocation online (IsOCSPEnabled).
pub fn signer(path: &str, revocation: bool) -> Option<String> {
    let file = std::fs::File::open(path).ok()?;
    let wide_path = wide(path);
    let mut info = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: PCWSTR(wide_path.as_ptr()),
        hFile: HANDLE(file.as_raw_handle()),
        ..Default::default()
    };
    if let Some(name) = verify(WTD_CHOICE_FILE.0, &mut info as *mut _ as *mut c_void, revocation) {
        return Some(name);
    }
    from_catalog(&file, &wide_path, revocation)
}

fn from_catalog(file: &std::fs::File, wide_path: &[u16], revocation: bool) -> Option<String> {
    // Catalogs hash with SHA-256 now; older ones use SHA-1 (the default).
    for algorithm in [Some("SHA256"), None] {
        unsafe {
            let mut admin = 0isize;
            let name = algorithm.map(wide);
            let name_ptr = name.as_ref().map_or(PCWSTR::null(), |n| PCWSTR(n.as_ptr()));
            if CryptCATAdminAcquireContext2(&mut admin, None, name_ptr, None, None).is_err() {
                continue;
            }
            let handle = HANDLE(file.as_raw_handle());
            let mut size = 0u32;
            let _ = CryptCATAdminCalcHashFromFileHandle2(admin, handle, &mut size, None, None);
            let mut hash = vec![0u8; size as usize];
            let mut result = None;
            if size > 0 && CryptCATAdminCalcHashFromFileHandle2(admin, handle, &mut size, Some(hash.as_mut_ptr()), None).is_ok() {
                let catalog = CryptCATAdminEnumCatalogFromHash(admin, &hash, None, None);
                if catalog != 0 {
                    let mut catalog_info = CATALOG_INFO {
                        cbStruct: std::mem::size_of::<CATALOG_INFO>() as u32,
                        ..Default::default()
                    };
                    if CryptCATCatalogInfoFromContext(catalog, &mut catalog_info, 0).is_ok() {
                        let tag = wide(&hash.iter().map(|b| format!("{b:02X}")).collect::<String>());
                        let mut info = WINTRUST_CATALOG_INFO {
                            cbStruct: std::mem::size_of::<WINTRUST_CATALOG_INFO>() as u32,
                            pcwszCatalogFilePath: PCWSTR(catalog_info.wszCatalogFile.as_ptr()),
                            pcwszMemberTag: PCWSTR(tag.as_ptr()),
                            pcwszMemberFilePath: PCWSTR(wide_path.as_ptr()),
                            hMemberFile: handle,
                            pbCalculatedFileHash: hash.as_mut_ptr(),
                            cbCalculatedFileHash: hash.len() as u32,
                            hCatAdmin: admin,
                            ..Default::default()
                        };
                        result = verify(WTD_CHOICE_CATALOG.0, &mut info as *mut _ as *mut c_void, revocation);
                    }
                    let _ = CryptCATAdminReleaseCatalogContext(admin, catalog, 0);
                }
            }
            let _ = CryptCATAdminReleaseContext(admin, 0);
            if result.is_some() {
                return result;
            }
        }
    }
    None
}

fn verify(choice: u32, union: *mut c_void, revocation: bool) -> Option<String> {
    let mut action: GUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let mut data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: if revocation { WTD_REVOKE_WHOLECHAIN } else { WTD_REVOKE_NONE },
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: if revocation { WTD_SAFER_FLAG } else { WTD_SAFER_FLAG | WTD_CACHE_ONLY_URL_RETRIEVAL },
        ..Default::default()
    };
    data.dwUnionChoice.0 = choice;
    // Both union members are pointers; the choice above says which one it is.
    data.Anonymous.pFile = union as *mut WINTRUST_FILE_INFO;
    unsafe {
        let status = WinVerifyTrust(HWND(-1isize as *mut c_void), &mut action, &mut data as *mut _ as *mut c_void);
        let name = (status == 0 && !data.hWVTStateData.is_invalid()).then(|| signer_name(data.hWVTStateData)).flatten();
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(HWND(-1isize as *mut c_void), &mut action, &mut data as *mut _ as *mut c_void);
        if status == 0 {
            Some(name.unwrap_or_default())
        } else {
            None
        }
    }
}

/// The common name of the first certificate in the signer chain (`_app_verifygetstring`).
unsafe fn signer_name(state: HANDLE) -> Option<String> {
    let provider = WTHelperProvDataFromStateData(state);
    if provider.is_null() {
        return None;
    }
    let signer = WTHelperGetProvSignerFromChain(provider, 0, false, 0);
    if signer.is_null() {
        return None;
    }
    let cert = WTHelperGetProvCertFromChain(signer, 0);
    if cert.is_null() || (*cert).pCert.is_null() {
        return None;
    }
    // szOID_COMMON_NAME
    let oid = b"2.5.4.3\0";
    let mut buf = [0u16; 256];
    let len = CertGetNameStringW((*cert).pCert, CERT_NAME_ATTR_TYPE, 0, Some(oid.as_ptr() as *const c_void), Some(&mut buf));
    (len > 1).then(|| String::from_utf16_lossy(&buf[..len as usize - 1]))
}

/// SHA-256 of a file as uppercase hex, like `_r_crypt_getfilehash`.
pub fn file_sha256(path: &str) -> Option<String> {
    use windows::Win32::Security::Cryptography::{
        BCryptCloseAlgorithmProvider, BCryptCreateHash, BCryptDestroyHash, BCryptFinishHash, BCryptHashData,
        BCryptOpenAlgorithmProvider, BCRYPT_ALG_HANDLE, BCRYPT_HASH_HANDLE, BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS,
        BCRYPT_SHA256_ALGORITHM,
    };
    use std::io::Read;
    let mut file = std::fs::File::open(path).ok()?;
    unsafe {
        let mut alg = BCRYPT_ALG_HANDLE::default();
        BCryptOpenAlgorithmProvider(&mut alg, BCRYPT_SHA256_ALGORITHM, PCWSTR::null(), BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS(0))
            .ok()
            .ok()?;
        let mut hash = BCRYPT_HASH_HANDLE::default();
        let mut out = [0u8; 32];
        let mut ok = BCryptCreateHash(alg, &mut hash, None, None, 0).is_ok();
        let mut buf = vec![0u8; 1 << 16];
        while ok {
            match file.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => ok = BCryptHashData(hash, &buf[..n], 0).is_ok(),
                Err(_) => ok = false,
            }
        }
        ok = ok && BCryptFinishHash(hash, &mut out, 0).is_ok();
        let _ = BCryptDestroyHash(hash);
        let _ = BCryptCloseAlgorithmProvider(alg, 0);
        ok.then(|| out.iter().map(|b| format!("{b:02X}")).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_binaries_are_signed_by_microsoft() {
        let root = std::env::var("SystemRoot").unwrap();
        // notepad.exe is catalog-signed on current Windows; explorer.exe has an embedded signature.
        for name in ["notepad.exe", "explorer.exe"] {
            let signer = signer(&format!(r"{root}\{}", if name == "notepad.exe" { r"system32\notepad.exe" } else { name }), false);
            assert!(signer.as_deref().is_some_and(|s| s.contains("Microsoft")), "{name}: {signer:?}");
        }
    }

    #[test]
    fn unsigned_files_have_no_signer() {
        let path = std::env::temp_dir().join("firebreak-unsigned-test.exe");
        std::fs::write(&path, b"MZ not a real program").unwrap();
        assert_eq!(signer(&path.to_string_lossy(), false), None);
        assert_eq!(
            file_sha256(&path.to_string_lossy()).unwrap().len(),
            64
        );
        let _ = std::fs::remove_file(path);
    }
}
