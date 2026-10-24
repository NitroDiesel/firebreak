//! Notification-area icon, like the C build's tray. It runs on its own thread
//! with a hidden window, so it keeps working while the main window sits
//! minimized, and it adds itself back when Explorer restarts (TaskbarCreated),
//! which is what upstream #2133 and #2162 were about.
//!
//! The main window is never hidden: eframe stops calling `update` for hidden
//! windows, which would stop timers and notifications. "In the tray" means
//! minimized with its taskbar button removed.

use std::sync::atomic::{AtomicIsize, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Mutex, OnceLock};

use eframe::egui;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, POINT, WPARAM};
use windows::Win32::System::Com::{CoCreateInstance, CoInitializeEx, CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Shell::{
    ITaskbarList, Shell_NotifyIconW, TaskbarList, NIF_ICON, NIF_MESSAGE, NIF_SHOWTIP, NIF_TIP, NIM_ADD,
    NIM_DELETE, NIM_MODIFY, NIM_SETVERSION, NOTIFYICONDATAW, NOTIFYICON_VERSION_4,
};
use windows::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, ChangeWindowMessageFilterEx, CreateIconFromResourceEx, CreatePopupMenu, CreateWindowExW,
    DefWindowProcW, DestroyIcon, DestroyMenu, DestroyWindow, DispatchMessageW, FindWindowW, GetCursorPos,
    GetMessageW, GetSystemMetrics, IsIconic, PostMessageW, PostQuitMessage, RegisterClassW,
    RegisterWindowMessageW, SetForegroundWindow, ShowWindow, TrackPopupMenuEx, TranslateMessage, HICON, HMENU,
    LR_DEFAULTCOLOR, MF_CHECKED, MF_GRAYED, MF_POPUP, MF_SEPARATOR, MF_STRING, MSG, MSGFLT_ALLOW,
    SM_CXSMICON, SW_MINIMIZE, SW_RESTORE, TPM_BOTTOMALIGN, TPM_RETURNCMD, TPM_RIGHTBUTTON, WINDOW_EX_STYLE,
    WM_APP, WM_CLOSE, WM_CONTEXTMENU, WM_DESTROY, WM_NULL, WNDCLASSW, WS_OVERLAPPED,
};

use crate::apps::wide;

const CLASS: &str = "simplewall-rust-tray";
const WM_TRAY: u32 = WM_APP + 1;
/// `NIN_SELECT` and `NIN_KEYSELECT` (WM_USER, WM_USER | NINF_KEY); not exported by the windows crate.
const NIN_SELECT: u32 = 0x400;
const NIN_KEYSELECT: u32 = 0x401;
/// Posted by a second copy of simplewall, so it shows this one instead.
const WM_SHOW: u32 = WM_APP + 2;
const WM_REFRESH: u32 = WM_APP + 3;
/// wparam 1 = send the main window to the tray, 0 = bring it back.
const WM_MAIN: u32 = WM_APP + 4;

const ICON_ACTIVE: &[u8] = include_bytes!("../resources/icons/active.ico");
const ICON_INACTIVE: &[u8] = include_bytes!("../resources/icons/inactive.ico");

/// What the tray asks the window to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrayCommand {
    ToggleFilters,
    Notifications,
    NotificationSound,
    FullscreenSilent,
    LogFile,
    LogUi,
    ShowLog,
    ClearLog,
    Settings,
    Website,
    About,
    Exit,
}

/// Checkmarks and the icon. The window sends a new copy when anything changes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TrayState {
    pub filters_on: bool,
    pub busy: bool,
    pub notifications: bool,
    pub sound: bool,
    pub fullscreen_silent: bool,
    pub log_file: bool,
    pub log_ui: bool,
}

struct Shared {
    tx: Mutex<Sender<TrayCommand>>,
    ctx: egui::Context,
    state: Mutex<TrayState>,
    main: AtomicIsize,
}

static SHARED: OnceLock<Shared> = OnceLock::new();

pub struct Tray {
    hwnd: isize,
}

impl Tray {
    /// Start the tray thread. None if the icon could not be created.
    pub fn spawn(ctx: egui::Context, tx: Sender<TrayCommand>, state: TrayState) -> Option<Self> {
        SHARED
            .set(Shared {
                tx: Mutex::new(tx),
                ctx,
                state: Mutex::new(state),
                main: AtomicIsize::new(0),
            })
            .ok()?;
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || unsafe { run(ready_tx) });
        let hwnd = ready_rx.recv().ok().flatten()?;
        Some(Self { hwnd })
    }

    pub fn set_state(&self, state: TrayState) {
        if let Some(shared) = SHARED.get() {
            *shared.state.lock().unwrap() = state;
            self.post(WM_REFRESH, 0);
        }
    }

    pub fn set_main_window(&self, hwnd: isize) {
        if let Some(shared) = SHARED.get() {
            shared.main.store(hwnd, Ordering::Relaxed);
        }
    }

    /// Minimize the main window and drop its taskbar button.
    pub fn hide_main(&self) {
        self.post(WM_MAIN, 1);
    }

    pub fn show_main(&self) {
        self.post(WM_MAIN, 0);
    }

    fn post(&self, msg: u32, wparam: usize) {
        unsafe {
            let _ = PostMessageW(Some(HWND(self.hwnd as _)), msg, WPARAM(wparam), LPARAM(0));
        }
    }
}

impl Drop for Tray {
    fn drop(&mut self) {
        self.post(WM_CLOSE, 0);
    }
}

/// If simplewall is already running, bring its window up and return true.
pub fn signal_running_instance() -> bool {
    let class = wide(CLASS);
    unsafe {
        match FindWindowW(PCWSTR(class.as_ptr()), PCWSTR::null()) {
            Ok(hwnd) if !hwnd.0.is_null() => PostMessageW(Some(hwnd), WM_SHOW, WPARAM(0), LPARAM(0)).is_ok(),
            _ => false,
        }
    }
}

unsafe fn run(ready: std::sync::mpsc::Sender<Option<isize>>) {
    let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
    let class = wide(CLASS);
    let instance = GetModuleHandleW(None).ok().map(|m| m.into());
    let wc = WNDCLASSW {
        lpfnWndProc: Some(wndproc),
        hInstance: instance.unwrap_or_default(),
        lpszClassName: PCWSTR(class.as_ptr()),
        ..Default::default()
    };
    RegisterClassW(&wc);
    let title = wide("simplewall tray");
    let hwnd = match CreateWindowExW(
        WINDOW_EX_STYLE(0),
        PCWSTR(class.as_ptr()),
        PCWSTR(title.as_ptr()),
        WS_OVERLAPPED,
        0,
        0,
        0,
        0,
        None,
        None,
        instance,
        None,
    ) {
        Ok(hwnd) => hwnd,
        Err(_) => {
            let _ = ready.send(None);
            return;
        }
    };
    // A second copy may run without elevation; let its message through.
    let _ = ChangeWindowMessageFilterEx(hwnd, WM_SHOW, MSGFLT_ALLOW, None);
    add_icon(hwnd);
    let _ = ready.send(Some(hwnd.0 as isize));

    let mut msg = MSG::default();
    while GetMessageW(&mut msg, None, 0, 0).as_bool() {
        let _ = TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
}

fn taskbar_created() -> u32 {
    static ID: OnceLock<u32> = OnceLock::new();
    *ID.get_or_init(|| {
        let name = wide("TaskbarCreated");
        unsafe { RegisterWindowMessageW(PCWSTR(name.as_ptr())) }
    })
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    let Some(shared) = SHARED.get() else {
        return DefWindowProcW(hwnd, msg, wparam, lparam);
    };
    match msg {
        WM_TRAY => {
            let event = (lparam.0 & 0xFFFF) as u32;
            if event == NIN_SELECT || event == NIN_KEYSELECT {
                toggle_main(shared);
            } else if event == WM_CONTEXTMENU {
                if let Some(command) = context_menu(hwnd, shared) {
                    let _ = shared.tx.lock().unwrap().send(command);
                    shared.ctx.request_repaint();
                }
            }
            LRESULT(0)
        }
        WM_SHOW => {
            show_main(shared);
            LRESULT(0)
        }
        WM_REFRESH => {
            modify_icon(hwnd, NIM_MODIFY);
            LRESULT(0)
        }
        WM_MAIN => {
            if wparam.0 == 1 {
                hide_main(shared);
            } else {
                show_main(shared);
            }
            LRESULT(0)
        }
        WM_CLOSE => {
            let mut data = icon_data(hwnd);
            let _ = Shell_NotifyIconW(NIM_DELETE, &data);
            let _ = DestroyWindow(hwnd);
            LRESULT(0)
        }
        WM_DESTROY => {
            PostQuitMessage(0);
            LRESULT(0)
        }
        _ if msg == taskbar_created() => {
            add_icon(hwnd);
            LRESULT(0)
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

fn icon_data(hwnd: HWND) -> NOTIFYICONDATAW {
    NOTIFYICONDATAW {
        cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
        hWnd: hwnd,
        uID: 1,
        ..Default::default()
    }
}

unsafe fn add_icon(hwnd: HWND) {
    modify_icon(hwnd, NIM_ADD);
    let mut data = icon_data(hwnd);
    data.Anonymous.uVersion = NOTIFYICON_VERSION_4;
    let _ = Shell_NotifyIconW(NIM_SETVERSION, &data);
}

unsafe fn modify_icon(hwnd: HWND, op: windows::Win32::UI::Shell::NOTIFY_ICON_MESSAGE) {
    let Some(shared) = SHARED.get() else {
        return;
    };
    let state = shared.state.lock().unwrap().clone();
    let mut data = icon_data(hwnd);
    data.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP | NIF_SHOWTIP;
    data.uCallbackMessage = WM_TRAY;
    let icon = load_icon(if state.filters_on { ICON_ACTIVE } else { ICON_INACTIVE });
    data.hIcon = icon.unwrap_or_default();
    let tip = if state.busy {
        "simplewall\nApplying filters"
    } else if state.filters_on {
        "simplewall\nFilters are enabled."
    } else {
        "simplewall\nFilters are disabled!"
    };
    for (slot, ch) in data.szTip.iter_mut().zip(tip.encode_utf16().take(127)) {
        *slot = ch;
    }
    let _ = Shell_NotifyIconW(op, &data);
    if let Some(icon) = icon {
        // The shell keeps its own copy.
        let _ = DestroyIcon(icon);
    }
}

/// Pick the .ico entry closest to the small-icon size and load it.
unsafe fn load_icon(ico: &[u8]) -> Option<HICON> {
    let want = GetSystemMetrics(SM_CXSMICON).max(16) as u32;
    let count = u16::from_le_bytes([*ico.get(4)?, *ico.get(5)?]) as usize;
    let mut best: Option<(u32, usize, usize)> = None;
    for i in 0..count {
        let entry = ico.get(6 + i * 16..6 + i * 16 + 16)?;
        let size = if entry[0] == 0 { 256 } else { entry[0] as u32 };
        let len = u32::from_le_bytes(entry[8..12].try_into().ok()?) as usize;
        let offset = u32::from_le_bytes(entry[12..16].try_into().ok()?) as usize;
        // Prefer the smallest image at least as large as wanted.
        let score = if size >= want { size - want } else { 1000 + want - size };
        if best.is_none_or(|(s, _, _)| score < s) {
            best = Some((score, offset, len));
        }
    }
    let (_, offset, len) = best?;
    let bits = ico.get(offset..offset + len)?;
    CreateIconFromResourceEx(bits, true, 0x0003_0000, want as i32, want as i32, LR_DEFAULTCOLOR).ok()
}

fn main_hwnd(shared: &Shared) -> Option<HWND> {
    let raw = shared.main.load(Ordering::Relaxed);
    (raw != 0).then_some(HWND(raw as _))
}

unsafe fn taskbar() -> Option<ITaskbarList> {
    let list: ITaskbarList = CoCreateInstance(&TaskbarList, None, CLSCTX_INPROC_SERVER).ok()?;
    list.HrInit().ok()?;
    Some(list)
}

unsafe fn show_main(shared: &Shared) {
    if let Some(main) = main_hwnd(shared) {
        let _ = ShowWindow(main, SW_RESTORE);
        if let Some(list) = taskbar() {
            let _ = list.AddTab(main);
        }
        let _ = SetForegroundWindow(main);
    }
    shared.ctx.request_repaint();
}

unsafe fn hide_main(shared: &Shared) {
    if let Some(main) = main_hwnd(shared) {
        if !IsIconic(main).as_bool() {
            let _ = ShowWindow(main, SW_MINIMIZE);
        }
        if let Some(list) = taskbar() {
            let _ = list.DeleteTab(main);
        }
    }
}

unsafe fn toggle_main(shared: &Shared) {
    match main_hwnd(shared) {
        Some(main) if IsIconic(main).as_bool() => show_main(shared),
        Some(_) => hide_main(shared),
        None => {}
    }
}

const ID_SHOW: usize = 1;
const COMMANDS: [(usize, TrayCommand); 12] = [
    (10, TrayCommand::ToggleFilters),
    (11, TrayCommand::Notifications),
    (12, TrayCommand::NotificationSound),
    (13, TrayCommand::FullscreenSilent),
    (14, TrayCommand::LogFile),
    (15, TrayCommand::LogUi),
    (16, TrayCommand::ShowLog),
    (17, TrayCommand::ClearLog),
    (18, TrayCommand::Settings),
    (19, TrayCommand::Website),
    (20, TrayCommand::About),
    (21, TrayCommand::Exit),
];

fn id_of(command: TrayCommand) -> usize {
    COMMANDS.iter().find(|(_, c)| *c == command).map_or(0, |(id, _)| *id)
}

/// The C build's tray menu, with the same items and labels.
unsafe fn context_menu(hwnd: HWND, shared: &Shared) -> Option<TrayCommand> {
    let state = shared.state.lock().unwrap().clone();
    let check = |on: bool| if on { MF_STRING | MF_CHECKED } else { MF_STRING };
    let menu = CreatePopupMenu().ok()?;
    let notify = CreatePopupMenu().ok()?;
    let log = CreatePopupMenu().ok()?;
    let add = |m: HMENU, flags, id: usize, text: &str| {
        let text = wide(text);
        let _ = AppendMenuW(m, flags, id, PCWSTR(text.as_ptr()));
    };
    let sep = |m: HMENU| {
        let _ = AppendMenuW(m, MF_SEPARATOR, 0, PCWSTR::null());
    };

    add(menu, MF_STRING, ID_SHOW, "Show/Hide");
    sep(menu);
    let filters = if state.filters_on { "Disable filters" } else { "Enable filters" };
    let busy = if state.busy { MF_GRAYED } else { MF_STRING };
    add(menu, MF_STRING | busy, id_of(TrayCommand::ToggleFilters), filters);
    sep(menu);
    add(notify, check(state.notifications), id_of(TrayCommand::Notifications), "Enable packets notifications");
    let off = if state.notifications { MF_STRING } else { MF_GRAYED };
    add(notify, check(state.sound) | off, id_of(TrayCommand::NotificationSound), "Enable notifications sound");
    add(
        notify,
        check(state.fullscreen_silent) | off,
        id_of(TrayCommand::FullscreenSilent),
        "Enable silent-mode when full screen app in foreground",
    );
    add(menu, MF_POPUP, notify.0 as usize, "Notifications");
    add(log, check(state.log_file), id_of(TrayCommand::LogFile), "Enable packets logging to a file");
    add(log, check(state.log_ui), id_of(TrayCommand::LogUi), "Enable packets logging interface (session only)");
    sep(log);
    add(log, MF_STRING, id_of(TrayCommand::ShowLog), "Show log");
    add(log, MF_STRING, id_of(TrayCommand::ClearLog), "Clear log");
    add(menu, MF_POPUP, log.0 as usize, "Packets log");
    sep(menu);
    add(menu, MF_STRING, id_of(TrayCommand::Settings), "Settings...");
    add(menu, MF_STRING, id_of(TrayCommand::Website), "Website");
    add(menu, MF_STRING, id_of(TrayCommand::About), "About");
    sep(menu);
    add(menu, MF_STRING, id_of(TrayCommand::Exit), "Exit");

    let mut point = POINT::default();
    let _ = GetCursorPos(&mut point);
    // Without this the menu does not close when clicking elsewhere.
    let _ = SetForegroundWindow(hwnd);
    let chosen = TrackPopupMenuEx(
        menu,
        (TPM_RETURNCMD | TPM_RIGHTBUTTON | TPM_BOTTOMALIGN).0,
        point.x,
        point.y,
        hwnd,
        None,
    )
    .0 as usize;
    let _ = PostMessageW(Some(hwnd), WM_NULL, WPARAM(0), LPARAM(0));
    let _ = DestroyMenu(menu); // also destroys the submenus

    if chosen == ID_SHOW {
        toggle_main(shared);
        return None;
    }
    let command = COMMANDS.iter().find(|(id, _)| *id == chosen).map(|(_, c)| *c)?;
    if matches!(command, TrayCommand::Settings | TrayCommand::About) {
        show_main(shared);
    }
    Some(command)
}

