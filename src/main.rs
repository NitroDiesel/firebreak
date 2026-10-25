//! Rust port of henrypp/simplewall (GPL-3.0).
//! The C sources live in `D:\Coding\simplewall-master`. This crate keeps the
//! WFP provider, the internal rule list, the rule syntax, and the command line.

#![cfg_attr(not(test), windows_subsystem = "windows")]

mod apps;
mod autorun;
mod cli;
mod log;
mod model;
mod i18n;
mod netevents;
mod profile;
mod rules;
mod security;
mod swc;
mod tray;
mod udptrace;
mod ui;
mod update;
mod wufix;
mod wfp;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::Console::{
    AttachConsole, GetStdHandle, SetStdHandle, ATTACH_PARENT_PROCESS, STD_ERROR_HANDLE, STD_OUTPUT_HANDLE,
};
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

/// Passed to the elevated copy so it does not try to elevate again.
pub const ELEVATED_FLAG: &str = "-elevated";
/// Start in the tray. Used by the "Load on system startup" task.
pub const MINIMIZED_FLAG: &str = "-minimized";

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let has = |args: &[String], flag: &str| args.iter().any(|a| a.eq_ignore_ascii_case(flag));
    let relaunched = has(&args, ELEVATED_FLAG);
    let minimized = has(&args, MINIMIZED_FLAG);
    args.retain(|a| !a.eq_ignore_ascii_case(ELEVATED_FLAG) && !a.eq_ignore_ascii_case(MINIMIZED_FLAG));
    if !args.is_empty() {
        attach_parent_console();
        let code = cli::run(&args);
        std::process::exit(code);
    }
    // One window at a time, as in the C build: a second launch shows the first.
    if tray::signal_running_instance() {
        return;
    }
    // Filters need an elevated token, like the C build's requireAdministrator
    // manifest. The skip-UAC task elevates without a prompt; otherwise ask.
    // If the prompt is declined the window still opens read-only.
    if !relaunched && !wfp::is_admin() && (autorun::run_skip_uac() || relaunch_elevated(minimized)) {
        return;
    }
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([980.0, 660.0])
            .with_min_inner_size([640.0, 400.0])
            .with_title("simplewall")
            .with_icon(
                eframe::icon_data::from_png_bytes(include_bytes!("../resources/icons/simplewall.png"))
                    .unwrap_or_default(),
            ),
        ..Default::default()
    };
    if let Err(err) = eframe::run_native(
        "simplewall",
        options,
        Box::new(move |cc| Ok(Box::new(ui::SimplewallApp::new(cc, minimized)))),
    ) {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

fn relaunch_elevated(minimized: bool) -> bool {
    let Ok(exe) = std::env::current_exe() else {
        return false;
    };
    let verb = apps::wide("runas");
    let file = apps::wide(&exe.to_string_lossy());
    let params = if minimized {
        apps::wide(&format!("{ELEVATED_FLAG} {MINIMIZED_FLAG}"))
    } else {
        apps::wide(ELEVATED_FLAG)
    };
    let result = unsafe {
        ShellExecuteW(
            None,
            PCWSTR(verb.as_ptr()),
            PCWSTR(file.as_ptr()),
            PCWSTR(params.as_ptr()),
            PCWSTR::null(),
            SW_SHOWNORMAL,
        )
    };
    result.0 as isize > 32
}

/// The exe uses the GUI subsystem so no console window appears. For the command
/// line, write to inherited handles when output is redirected; otherwise borrow
/// the console of whatever started us.
fn attach_parent_console() {
    let valid = |std| unsafe { GetStdHandle(std).is_ok_and(|h| !h.is_invalid() && !h.0.is_null()) };
    if valid(STD_OUTPUT_HANDLE) {
        return;
    }
    unsafe {
        if AttachConsole(ATTACH_PARENT_PROCESS).is_err() {
            return;
        }
        let path = apps::wide("CONOUT$");
        let Ok(console) = CreateFileW(
            PCWSTR(path.as_ptr()),
            (GENERIC_READ | GENERIC_WRITE).0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            None,
        ) else {
            return;
        };
        let _ = SetStdHandle(STD_OUTPUT_HANDLE, console);
        if !valid(STD_ERROR_HANDLE) {
            let _ = SetStdHandle(STD_ERROR_HANDLE, console);
        }
    }
    // The shell printed its prompt already; start on a fresh line.
    println!();
}
