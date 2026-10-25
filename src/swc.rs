//! Reads profiles written by the C build. A plain profile is XML. A compressed
//! or encrypted one starts with a header (db.h):
//!
//! | offset | length | contents                                   |
//! |--------|--------|--------------------------------------------|
//! | 0      | 3      | "SWC"                                      |
//! | 3      | 1      | 0x30 plain, 0x31 compressed, 0x32 encrypted |
//! | 4      | 32     | SHA-256 of the decoded body                |
//! | 36     | ...    | body                                       |
//!
//! Compressed bodies are LZNT1 (or XPRESS); encrypted ones are AES-CBC with a
//! zero IV and the key in PROFILE2_KEY_DEPRECATED, as in `_app_db_decodebody`.

use windows::core::PCWSTR;
use windows::Win32::Security::Cryptography::{
    BCryptCloseAlgorithmProvider, BCryptDecrypt, BCryptDestroyKey, BCryptGenerateSymmetricKey, BCryptHash,
    BCryptOpenAlgorithmProvider, BCryptSetProperty, BCRYPT_AES_ALGORITHM, BCRYPT_ALG_HANDLE, BCRYPT_BLOCK_PADDING,
    BCRYPT_CHAINING_MODE, BCRYPT_CHAIN_MODE_CBC, BCRYPT_KEY_HANDLE, BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS,
    BCRYPT_SHA256_ALGORITHM,
};

const FOURCC: &[u8] = b"SWC";
const HEADER: usize = 36;
const PLAIN: u8 = 0x30;
const COMPRESSED: u8 = 0x31;
const ENCRYPTED: u8 = 0x32;
const KEY: &[u8] = b"Gc(j1EptodnKP?{ZT!SlMVip[fJIs&Ci3fOqjATfp@h,q0(]QVaGs5Iht3)/b:Ll";
const COMPRESSION_FORMAT_LZNT1: u16 = 2;
const COMPRESSION_FORMAT_XPRESS: u16 = 3;

#[link(name = "ntdll", kind = "raw-dylib")]
extern "system" {
    fn RtlDecompressBuffer(
        format: u16,
        uncompressed: *mut u8,
        uncompressed_size: u32,
        compressed: *const u8,
        compressed_size: u32,
        final_size: *mut u32,
    ) -> i32;
}

/// Profile bytes to XML text, whatever format the C build saved them in.
pub fn decode(bytes: &[u8]) -> Result<String, String> {
    let mut data = bytes.to_vec();
    // A body can itself start with a header (STATUS_MORE_PROCESSING_REQUIRED in db.c).
    for _ in 0..3 {
        if data.len() < HEADER || &data[..3] != FOURCC {
            break;
        }
        let hash = data[4..HEADER].to_vec();
        let body = &data[HEADER..];
        let plain = match data[3] {
            PLAIN => body.to_vec(),
            COMPRESSED => decompress(body)?,
            ENCRYPTED => decrypt(body)?,
            other => return Err(format!("Unknown profile type 0x{other:02X}.")),
        };
        if sha256(&plain)? != hash {
            return Err("The profile checksum does not match; the file is damaged.".into());
        }
        data = plain;
    }
    text(&data)
}

/// UTF-8 (with or without a byte order mark) or UTF-16 LE.
fn text(bytes: &[u8]) -> Result<String, String> {
    if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        let units: Vec<u16> = rest.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        return Ok(String::from_utf16_lossy(&units));
    }
    let bytes = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    String::from_utf8(bytes.to_vec()).map_err(|_| "The profile is not valid text.".to_string())
}

fn decompress(body: &[u8]) -> Result<Vec<u8>, String> {
    const STATUS_BAD_COMPRESSION_BUFFER: i32 = 0xC000_0242_u32 as i32;
    for format in [COMPRESSION_FORMAT_LZNT1, COMPRESSION_FORMAT_XPRESS] {
        let mut size = (body.len() * 4).max(4096);
        for _ in 0..8 {
            let mut out = vec![0u8; size];
            let mut written = 0u32;
            let status = unsafe {
                RtlDecompressBuffer(format, out.as_mut_ptr(), size as u32, body.as_ptr(), body.len() as u32, &mut written)
            };
            if status >= 0 {
                out.truncate(written as usize);
                return Ok(out);
            }
            if status != STATUS_BAD_COMPRESSION_BUFFER {
                break;
            }
            size *= 2;
        }
    }
    Err("The compressed profile could not be decompressed.".into())
}

struct Alg(BCRYPT_ALG_HANDLE);

impl Alg {
    fn open(id: PCWSTR) -> Result<Self, String> {
        let mut handle = BCRYPT_ALG_HANDLE::default();
        unsafe { BCryptOpenAlgorithmProvider(&mut handle, id, PCWSTR::null(), BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS(0)) }
            .ok()
            .map_err(|e| e.to_string())?;
        Ok(Self(handle))
    }
}

impl Drop for Alg {
    fn drop(&mut self) {
        unsafe {
            let _ = BCryptCloseAlgorithmProvider(self.0, 0);
        }
    }
}

fn decrypt(body: &[u8]) -> Result<Vec<u8>, String> {
    let fail = |e: windows::core::Error| format!("The encrypted profile could not be decrypted ({e}).");
    let alg = Alg::open(BCRYPT_AES_ALGORITHM)?;
    unsafe {
        let mode: Vec<u16> = BCRYPT_CHAIN_MODE_CBC.as_wide().iter().copied().chain([0]).collect();
        let mode_bytes = std::slice::from_raw_parts(mode.as_ptr() as *const u8, mode.len() * 2);
        BCryptSetProperty(alg.0.into(), BCRYPT_CHAINING_MODE, mode_bytes, 0).ok().map_err(fail)?;
        let mut key = BCRYPT_KEY_HANDLE::default();
        BCryptGenerateSymmetricKey(alg.0, &mut key, None, KEY, 0).ok().map_err(fail)?;
        let mut iv = [0u8; 16];
        let mut size = 0u32;
        let result = BCryptDecrypt(key, Some(body), None, Some(&mut iv), None, &mut size, BCRYPT_BLOCK_PADDING)
            .ok()
            .and_then(|()| {
                let mut out = vec![0u8; size as usize];
                let mut iv = [0u8; 16];
                BCryptDecrypt(key, Some(body), None, Some(&mut iv), Some(&mut out), &mut size, BCRYPT_BLOCK_PADDING)
                    .ok()
                    .map(|()| {
                        out.truncate(size as usize);
                        out
                    })
            });
        let _ = BCryptDestroyKey(key);
        result.map_err(fail)
    }
}

fn sha256(data: &[u8]) -> Result<Vec<u8>, String> {
    let alg = Alg::open(BCRYPT_SHA256_ALGORITHM)?;
    let mut out = vec![0u8; 32];
    unsafe { BCryptHash(alg.0, None, data, &mut out) }.ok().map_err(|e| e.to_string())?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_text_passes_through() {
        assert_eq!(decode(b"<root />").unwrap(), "<root />");
        assert_eq!(decode(b"\xEF\xBB\xBF<root />").unwrap(), "<root />");
        let utf16: Vec<u8> = [0xFF, 0xFE].into_iter().chain("<root />".encode_utf16().flat_map(u16::to_le_bytes)).collect();
        assert_eq!(decode(&utf16).unwrap(), "<root />");
    }

    #[test]
    fn plain_header_checks_the_hash() {
        let body = b"<root version=\"5\" />";
        let mut file = b"SWC\x30".to_vec();
        file.extend(sha256(body).unwrap());
        file.extend(body);
        assert_eq!(decode(&file).unwrap(), "<root version=\"5\" />");
        let last = file.len() - 1;
        file[last] = b'!';
        assert!(decode(&file).is_err());
    }
}

/// How the C build can save a profile (ProfileType).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Plain,
    Compressed,
    Encrypted,
}

impl Format {
    pub fn from_setting(value: u64) -> Self {
        match value {
            1 => Self::Compressed,
            2 => Self::Encrypted,
            _ => Self::Plain,
        }
    }
}

/// XML to profile bytes, as `_app_db_encodebody` writes them. Plain stays bare
/// XML; the other formats get the SWC header with the SHA-256 of the XML.
pub fn encode(text: &str, format: Format) -> Result<Vec<u8>, String> {
    let plain = text.as_bytes();
    let (kind, body) = match format {
        Format::Plain => return Ok(plain.to_vec()),
        Format::Compressed => (COMPRESSED, compress(plain)?),
        Format::Encrypted => (ENCRYPTED, encrypt(plain)?),
    };
    let mut file = FOURCC.to_vec();
    file.push(kind);
    file.extend(sha256(plain)?);
    file.extend(body);
    Ok(file)
}

#[link(name = "ntdll", kind = "raw-dylib")]
extern "system" {
    fn RtlGetCompressionWorkSpaceSize(format: u16, buffer_ws: *mut u32, fragment_ws: *mut u32) -> i32;
    fn RtlCompressBuffer(
        format: u16,
        uncompressed: *const u8,
        uncompressed_size: u32,
        compressed: *mut u8,
        compressed_size: u32,
        chunk_size: u32,
        final_size: *mut u32,
        workspace: *mut u8,
    ) -> i32;
}

/// LZNT1 at maximum compression (COMPRESSION_ENGINE_MAXIMUM), as the C build saves.
fn compress(data: &[u8]) -> Result<Vec<u8>, String> {
    const ENGINE_MAXIMUM: u16 = 0x0100;
    let format = COMPRESSION_FORMAT_LZNT1 | ENGINE_MAXIMUM;
    let fail = || "The profile could not be compressed.".to_string();
    let (mut ws, mut frag) = (0u32, 0u32);
    // LZNT1 can grow incompressible data slightly.
    let mut out = vec![0u8; data.len() + data.len() / 8 + 4096];
    let mut size = 0u32;
    unsafe {
        if RtlGetCompressionWorkSpaceSize(format, &mut ws, &mut frag) < 0 {
            return Err(fail());
        }
        let mut work = vec![0u8; ws as usize];
        let status = RtlCompressBuffer(
            format,
            data.as_ptr(),
            data.len() as u32,
            out.as_mut_ptr(),
            out.len() as u32,
            4096,
            &mut size,
            work.as_mut_ptr(),
        );
        if status < 0 {
            return Err(fail());
        }
    }
    out.truncate(size as usize);
    Ok(out)
}

fn encrypt(data: &[u8]) -> Result<Vec<u8>, String> {
    use windows::Win32::Security::Cryptography::BCryptEncrypt;
    let fail = |e: windows::core::Error| format!("The profile could not be encrypted ({e}).");
    let alg = Alg::open(BCRYPT_AES_ALGORITHM)?;
    unsafe {
        let mode: Vec<u16> = BCRYPT_CHAIN_MODE_CBC.as_wide().iter().copied().chain([0]).collect();
        let mode_bytes = std::slice::from_raw_parts(mode.as_ptr() as *const u8, mode.len() * 2);
        BCryptSetProperty(alg.0.into(), BCRYPT_CHAINING_MODE, mode_bytes, 0).ok().map_err(fail)?;
        let mut key = BCRYPT_KEY_HANDLE::default();
        BCryptGenerateSymmetricKey(alg.0, &mut key, None, KEY, 0).ok().map_err(fail)?;
        let mut size = 0u32;
        let mut iv = [0u8; 16];
        let result = BCryptEncrypt(key, Some(data), None, Some(&mut iv), None, &mut size, BCRYPT_BLOCK_PADDING)
            .ok()
            .and_then(|()| {
                let mut out = vec![0u8; size as usize];
                let mut iv = [0u8; 16];
                BCryptEncrypt(key, Some(data), None, Some(&mut iv), Some(&mut out), &mut size, BCRYPT_BLOCK_PADDING)
                    .ok()
                    .map(|()| {
                        out.truncate(size as usize);
                        out
                    })
            });
        let _ = BCryptDestroyKey(key);
        result.map_err(fail)
    }
}

#[cfg(test)]
mod round_trip {
    use super::*;

    #[test]
    fn every_format_reads_back() {
        let xml = r#"<root version="5"><apps><item path="C:\a.exe" is_enabled="true" /></apps></root>"#.repeat(20);
        for format in [Format::Plain, Format::Compressed, Format::Encrypted] {
            let bytes = encode(&xml, format).unwrap();
            assert_eq!(bytes.starts_with(b"SWC"), format != Format::Plain);
            assert_eq!(decode(&bytes).unwrap(), xml, "{format:?}");
        }
        assert!(encode(&xml, Format::Compressed).unwrap().len() < xml.len() / 2);
    }
}
