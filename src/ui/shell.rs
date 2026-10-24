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
