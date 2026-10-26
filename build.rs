//! Embeds the icon, the manifest, and the version information (publisher
//! NitroDiesel) into simplewall.exe. The .rc is written here so its version
//! always matches Cargo.toml.

fn main() {
    let dir = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let path = |p: &str| dir.join(p).to_string_lossy().replace('\\', "\\\\");
    let version = env!("CARGO_PKG_VERSION");
    let mut parts: Vec<u16> = version.split('.').map(|p| p.parse().unwrap_or(0)).collect();
    parts.resize(4, 0);
    let numeric = parts.iter().map(u16::to_string).collect::<Vec<_>>().join(",");
    let rc = format!(
        r#"#include <winver.h>
1 ICON "{icon}"
1 24 "{manifest}"
VS_VERSION_INFO VERSIONINFO
FILEVERSION {numeric}
PRODUCTVERSION {numeric}
FILEOS VOS_NT_WINDOWS32
FILETYPE VFT_APP
BEGIN
  BLOCK "StringFileInfo"
  BEGIN
    BLOCK "040904B0"
    BEGIN
      VALUE "CompanyName", "NitroDiesel"
      VALUE "FileDescription", "simplewall (Rust)"
      VALUE "FileVersion", "{version}"
      VALUE "InternalName", "simplewall"
      VALUE "LegalCopyright", "GPL-3.0. Rust port by NitroDiesel, based on simplewall by Henry++"
      VALUE "OriginalFilename", "simplewall.exe"
      VALUE "ProductName", "simplewall (Rust)"
      VALUE "ProductVersion", "{version}"
    END
  END
  BLOCK "VarFileInfo"
  BEGIN
    VALUE "Translation", 0x409, 1200
  END
END
"#,
        icon = path("resources/icons/active.ico"),
        manifest = path("resources/simplewall.manifest"),
    );
    let file = out.join("simplewall.rc");
    std::fs::write(&file, rc).unwrap();
    embed_resource::compile(&file, embed_resource::NONE).manifest_required().unwrap();
    println!("cargo:rerun-if-changed=resources/simplewall.manifest");
    println!("cargo:rerun-if-changed=resources/icons/active.ico");
}
