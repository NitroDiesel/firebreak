//! Small Win32 helpers the window needs: accent color, file picker, shell open,
//! locale time format, and shell icons.

use eframe::egui::{Color32, ColorImage};
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{FILETIME, HWND, SYSTEMTIME};
use windows::Win32::Globalization::{GetDateFormatEx, GetTimeFormatEx, DATE_SHORTDATE, TIME_NOSECONDS};
use windows::Win32::Graphics::Gdi::{
    DeleteObject, GetDC, GetDIBits, ReleaseDC, BITMAPINFO, BITMAPINFOHEADER, BI_RGB, DIB_RGB_COLORS,
};
use windows::Win32::Storage::FileSystem::{FILE_ATTRIBUTE_NORMAL, FILE_FLAGS_AND_ATTRIBUTES};
use windows::Win32::System::Registry::{RegGetValueW, HKEY_CURRENT_USER, RRF_RT_REG_DWORD};
use windows::Win32::System::Time::{FileTimeToSystemTime, SystemTimeToTzSpecificLocalTime};
use windows::Win32::UI::Controls::Dialogs::{
    GetOpenFileNameW, OFN_EXPLORER, OFN_FILEMUSTEXIST, OFN_NOCHANGEDIR, OFN_PATHMUSTEXIST,
    OPENFILENAMEW,
};
use windows::Win32::UI::Shell::{
    SHGetFileInfoW, ShellExecuteW, SHFILEINFOW, SHGFI_ICON, SHGFI_LARGEICON, SHGFI_USEFILEATTRIBUTES,
};
use windows::Win32::UI::WindowsAndMessaging::{
    DestroyIcon, GetForegroundWindow, GetIconInfo, ICONINFO, SW_SHOWNORMAL,
};

use crate::apps::{utf16_prefix, wide};

/// Seconds between 1601-01-01 and 1970-01-01, in FILETIME ticks.
const FILETIME_UNIX_EPOCH: u64 = 116_444_736_000_000_000;

pub fn accent_color() -> Option<Color32> {
    let key = wide(r"Software\Microsoft\Windows\DWM");
    let name = wide("AccentColor");
    let mut value = 0u32;
    let mut size = 4u32;
    let err = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            PCWSTR(key.as_ptr()),
            PCWSTR(name.as_ptr()),
            RRF_RT_REG_DWORD,
            None,
            Some(&mut value as *mut u32 as *mut _),
            Some(&mut size),
        )
    };
    // Stored as 0xAABBGGRR.
    err.is_ok()
        .then(|| Color32::from_rgb(value as u8, (value >> 8) as u8, (value >> 16) as u8))
}

/// Modal "Open" dialog for an executable, owned by the foreground window.
pub fn pick_executable() -> Option<String> {
    let filter = wide("Executables (*.exe)\0*.exe\0All files (*.*)\0*.*\0");
    let mut file = vec![0u16; 4096];
    let mut ofn = OPENFILENAMEW {
        lStructSize: std::mem::size_of::<OPENFILENAMEW>() as u32,
        hwndOwner: unsafe { GetForegroundWindow() },
        lpstrFilter: PCWSTR(filter.as_ptr()),
        lpstrFile: PWSTR(file.as_mut_ptr()),
        nMaxFile: file.len() as u32,
        Flags: OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR,
        ..Default::default()
    };
    unsafe { GetOpenFileNameW(&mut ofn).as_bool() }.then(|| utf16_prefix(&file))
}

const PROFILE_FILTER: &str = "Profile files (*.xml)\0*.xml\0All files (*.*)\0*.*\0";

/// "Open" dialog for a profile to import.
pub fn pick_profile_to_open() -> Option<String> {
    let filter = wide(PROFILE_FILTER);
    let mut file = vec![0u16; 4096];
    let mut ofn = OPENFILENAMEW {
        lStructSize: std::mem::size_of::<OPENFILENAMEW>() as u32,
        hwndOwner: unsafe { GetForegroundWindow() },
        lpstrFilter: PCWSTR(filter.as_ptr()),
        lpstrFile: PWSTR(file.as_mut_ptr()),
        nMaxFile: file.len() as u32,
        Flags: OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR,
        ..Default::default()
    };
    unsafe { GetOpenFileNameW(&mut ofn).as_bool() }.then(|| utf16_prefix(&file))
}

/// "Save as" dialog for exporting the profile.
pub fn pick_profile_to_save() -> Option<String> {
    use windows::Win32::UI::Controls::Dialogs::{GetSaveFileNameW, OFN_OVERWRITEPROMPT};
    let filter = wide(PROFILE_FILTER);
    let extension = wide("xml");
    let mut file = vec![0u16; 4096];
    for (slot, ch) in file.iter_mut().zip("profile.xml".encode_utf16()) {
        *slot = ch;
    }
    let mut ofn = OPENFILENAMEW {
        lStructSize: std::mem::size_of::<OPENFILENAMEW>() as u32,
        hwndOwner: unsafe { GetForegroundWindow() },
        lpstrFilter: PCWSTR(filter.as_ptr()),
        lpstrFile: PWSTR(file.as_mut_ptr()),
        nMaxFile: file.len() as u32,
        lpstrDefExt: PCWSTR(extension.as_ptr()),
        Flags: OFN_EXPLORER | OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT | OFN_NOCHANGEDIR,
        ..Default::default()
    };
    unsafe { GetSaveFileNameW(&mut ofn).as_bool() }.then(|| utf16_prefix(&file))
}

/// Open a URL or document with its default handler.
pub fn open(target: &str) {
    let op = wide("open");
    let file = wide(target);
    unsafe {
        ShellExecuteW(
            None::<HWND>,
            PCWSTR(op.as_ptr()),
            PCWSTR(file.as_ptr()),
            PCWSTR::null(),
            PCWSTR::null(),
            SW_SHOWNORMAL,
        );
    }
}

/// Explorer window with `path` selected.
pub fn reveal(path: &str) {
    let _ = std::process::Command::new("explorer.exe")
        .arg(format!("/select,{path}"))
        .spawn();
}

/// Short date and time in the user's locale, like the "Added" column of the C build.
pub fn format_time(unix: u64) -> String {
    if unix == 0 {
        return String::new();
    }
    let ticks = unix * 10_000_000 + FILETIME_UNIX_EPOCH;
    let ft = FILETIME {
        dwLowDateTime: ticks as u32,
        dwHighDateTime: (ticks >> 32) as u32,
    };
    let mut utc = SYSTEMTIME::default();
    let mut local = SYSTEMTIME::default();
    unsafe {
        if FileTimeToSystemTime(&ft, &mut utc).is_err()
            || SystemTimeToTzSpecificLocalTime(None, &utc, &mut local).is_err()
        {
            return String::new();
        }
        let mut date = [0u16; 64];
        let mut time = [0u16; 64];
        GetDateFormatEx(PCWSTR::null(), DATE_SHORTDATE, Some(&local), PCWSTR::null(), Some(&mut date), PCWSTR::null());
        GetTimeFormatEx(PCWSTR::null(), TIME_NOSECONDS, Some(&local), PCWSTR::null(), Some(&mut time));
        format!("{} {}", utf16_prefix(&date), utf16_prefix(&time))
    }
}

/// 32px shell icon for a file. With `generic`, the icon for its extension only.
pub fn file_icon(path: &str, generic: bool) -> Option<ColorImage> {
    let wide_path = wide(path);
    let mut info = SHFILEINFOW::default();
    let mut flags = SHGFI_ICON | SHGFI_LARGEICON;
    let mut attrs = FILE_FLAGS_AND_ATTRIBUTES(0);
    if generic {
        flags |= SHGFI_USEFILEATTRIBUTES;
        attrs = FILE_ATTRIBUTE_NORMAL;
    }
    unsafe {
        let ok = SHGetFileInfoW(
            PCWSTR(wide_path.as_ptr()),
            attrs,
            Some(&mut info),
            std::mem::size_of::<SHFILEINFOW>() as u32,
            flags,
        );
        if ok == 0 || info.hIcon.is_invalid() {
            return None;
        }
        let image = icon_pixels(info);
        let _ = DestroyIcon(info.hIcon);
        image
    }
}

unsafe fn icon_pixels(info: SHFILEINFOW) -> Option<ColorImage> {
    let mut icon = ICONINFO::default();
    GetIconInfo(info.hIcon, &mut icon).ok()?;
    let mut bmi = BITMAPINFO::default();
    bmi.bmiHeader.biSize = std::mem::size_of::<BITMAPINFOHEADER>() as u32;
    let dc = GetDC(None);
    let mut out = None;
    if !icon.hbmColor.is_invalid() && GetDIBits(dc, icon.hbmColor, 0, 0, None, &mut bmi, DIB_RGB_COLORS) != 0 {
        let (w, h) = (bmi.bmiHeader.biWidth, bmi.bmiHeader.biHeight.abs());
        bmi.bmiHeader.biBitCount = 32;
        bmi.bmiHeader.biCompression = BI_RGB.0;
        bmi.bmiHeader.biHeight = -h;
        let mut bgra = vec![0u8; (w * h * 4) as usize];
        if w > 0
            && h > 0
            && GetDIBits(dc, icon.hbmColor, 0, h as u32, Some(bgra.as_mut_ptr() as *mut _), &mut bmi, DIB_RGB_COLORS) == h
        {
            let no_alpha = bgra.chunks_exact(4).all(|px| px[3] == 0);
            for px in bgra.chunks_exact_mut(4) {
                px.swap(0, 2);
                if no_alpha {
                    px[3] = 255;
                }
            }
            out = Some(ColorImage::from_rgba_unmultiplied([w as usize, h as usize], &bgra));
        }
    }
    ReleaseDC(None, dc);
    if !icon.hbmColor.is_invalid() {
        let _ = DeleteObject(icon.hbmColor.into());
    }
    if !icon.hbmMask.is_invalid() {
        let _ = DeleteObject(icon.hbmMask.into());
    }
    out
}

/// The desktop area not covered by the taskbar, in physical pixels.
pub fn work_area() -> Option<windows::Win32::Foundation::RECT> {
    use windows::Win32::UI::WindowsAndMessaging::{SystemParametersInfoW, SPI_GETWORKAREA, SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS};
    let mut rect = windows::Win32::Foundation::RECT::default();
    unsafe {
        SystemParametersInfoW(
            SPI_GETWORKAREA,
            0,
            Some(&mut rect as *mut _ as *mut _),
            SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS(0),
        )
        .ok()?;
    }
    Some(rect)
}

/// A full-screen game, video, or presentation is in front (`_r_wnd_isfullscreenmode`).
pub fn fullscreen_app_in_front() -> bool {
    use windows::Win32::UI::Shell::{
        SHQueryUserNotificationState, QUNS_BUSY, QUNS_PRESENTATION_MODE, QUNS_RUNNING_D3D_FULL_SCREEN,
    };
    matches!(
        unsafe { SHQueryUserNotificationState() },
        Ok(state) if state == QUNS_BUSY || state == QUNS_RUNNING_D3D_FULL_SCREEN || state == QUNS_PRESENTATION_MODE
    )
}

/// The C build's notification sound (NOTIFY_SOUND_NAME).
pub fn play_alert_sound() {
    use windows::Win32::Media::Audio::{PlaySoundW, SND_ALIAS, SND_ASYNC, SND_NODEFAULT};
    let name = wide("MailBeep");
    unsafe {
        let _ = PlaySoundW(PCWSTR(name.as_ptr()), None, SND_ALIAS | SND_ASYNC | SND_NODEFAULT);
    }
}

/// `AppsUseLightTheme` from Windows' personalization settings.
pub fn apps_use_light_theme() -> Option<bool> {
    let key = wide(r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
    let name = wide("AppsUseLightTheme");
    let mut value = 0u32;
    let mut size = 4u32;
    let err = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            PCWSTR(key.as_ptr()),
            PCWSTR(name.as_ptr()),
            RRF_RT_REG_DWORD,
            None,
            Some(&mut value as *mut u32 as *mut _),
            Some(&mut size),
        )
    };
    err.is_ok().then_some(value != 0)
}

/// The Windows font dialog (View > Font). Returns the face and size in points.
pub fn choose_font(face: &str, points: u64) -> Option<(String, u64)> {
    use windows::Win32::Graphics::Gdi::LOGFONTW;
    use windows::Win32::UI::Controls::Dialogs::{
        ChooseFontW, CHOOSEFONTW, CF_FORCEFONTEXIST, CF_INITTOLOGFONTSTRUCT, CF_NOVERTFONTS, CF_SCREENFONTS,
    };
    let mut font = LOGFONTW::default();
    let face = if face.is_empty() { "Segoe UI" } else { face };
    for (slot, ch) in font.lfFaceName.iter_mut().zip(face.encode_utf16().take(31)) {
        *slot = ch;
    }
    // Points to logical pixels at 96 DPI; negative means character height.
    font.lfHeight = -((if points == 0 { 10 } else { points } as i32) * 96 / 72);
    let mut dialog = CHOOSEFONTW {
        lStructSize: std::mem::size_of::<CHOOSEFONTW>() as u32,
        hwndOwner: unsafe { GetForegroundWindow() },
        lpLogFont: &mut font,
        Flags: CF_SCREENFONTS | CF_INITTOLOGFONTSTRUCT | CF_NOVERTFONTS | CF_FORCEFONTEXIST,
        ..Default::default()
    };
    if !unsafe { ChooseFontW(&mut dialog) }.as_bool() {
        return None;
    }
    let name = utf16_prefix(&font.lfFaceName);
    Some((name, (dialog.iPointSize / 10).max(6) as u64))
}

/// The file behind an installed font face, from the Fonts registry keys of the
/// machine and of the user. Collections ("A & B (TrueType)") match either name.
pub fn font_file(face: &str) -> Option<std::path::PathBuf> {
    use windows::Win32::System::Registry::{RegCloseKey, RegEnumValueW, RegOpenKeyExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ};
    let fonts_dir = std::path::PathBuf::from(std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into())).join("Fonts");
    let wanted = face.to_lowercase();
    let key_path = wide(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts");
    for root in [HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER] {
        let mut key = HKEY::default();
        if unsafe { RegOpenKeyExW(root, PCWSTR(key_path.as_ptr()), None, KEY_READ, &mut key) }.is_err() {
            continue;
        }
        let mut found = None;
        for index in 0.. {
            let mut name = [0u16; 512];
            let mut name_len = name.len() as u32;
            let mut data = [0u16; 512];
            let mut data_len = (data.len() * 2) as u32;
            let status = unsafe {
                RegEnumValueW(
                    key,
                    index,
                    Some(PWSTR(name.as_mut_ptr())),
                    &mut name_len,
                    None,
                    None,
                    Some(data.as_mut_ptr() as *mut u8),
                    Some(&mut data_len),
                )
            };
            if status.is_err() {
                break;
            }
            let label = String::from_utf16_lossy(&name[..name_len as usize]).to_lowercase();
            let label = label.split(" (").next().unwrap_or(&label).to_string();
            if label.split(" & ").any(|part| part.trim() == wanted) {
                let file = utf16_prefix(&data);
                let path = std::path::PathBuf::from(&file);
                found = Some(if path.is_absolute() { path } else { fonts_dir.join(file) });
                break;
            }
        }
        unsafe {
            let _ = RegCloseKey(key);
        }
        if found.is_some() {
            return found;
        }
    }
    None
}
