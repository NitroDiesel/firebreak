//! Command line, same verbs as the C build:
//! `-install`, `-install -temp`, `-install -silent`, `-uninstall`, `-help`.

use crate::log::{self, log_path};
use crate::model::now_unix;
use crate::profile;
use crate::wfp;

pub fn run(args: &[String]) -> i32 {
    let joined = args.join(" ").to_ascii_lowercase();
    if joined.contains("-help") || joined.contains("-?") || joined.contains("/?") {
        print_help();
        return 0;
    }
    if joined.contains("-uninstall") {
        return finish(wfp::uninstall());
    }
    if joined.contains("-install") {
        let temp = joined.contains("-temp");
        let silent = joined.contains("-silent");
        if !silent && !wfp::is_admin() {
            eprintln!("simplewall needs an elevated console to install filters.");
            return 1;
        }
        let mut profile = profile::load();
        if profile.apps.is_empty() {
            profile.apps = crate::apps::enumerate();
            let _ = profile::save(&profile);
        }
        profile.settings.filters_temporary = temp;
        let result = wfp::install(&profile, temp);
        if result.is_ok() && profile.settings.log_to_file {
            log::append_file(
                &log_path(),
                &format!("{}\tinstall\ttemp={temp}", now_unix()),
            );
        }
        return finish(result);
    }
    if joined.contains("-status") {
        return match wfp::filters_installed() {
            Ok(true) => {
                println!("filters are installed");
                0
            }
            Ok(false) => {
                println!("filters are not installed");
                0
            }
            Err(err) => {
                eprintln!("{err}");
                1
            }
        };
    }
    print_help();
    1
}

fn finish(result: Result<String, String>) -> i32 {
    match result {
        Ok(msg) => {
            println!("{msg}");
            0
        }
        Err(err) => {
            eprintln!("{err}");
            1
        }
    }
}

fn print_help() {
    println!(
        "\
simplewall {ver} (Rust port)

\"simplewall.exe -install\" - enable filtering.
\"simplewall.exe -install -temp\" - enable filtering until reboot.
\"simplewall.exe -install -silent\" - enable filtering without prompt.
\"simplewall.exe -uninstall\" - remove all installed filters.
\"simplewall.exe -status\" - report whether the provider is installed.
\"simplewall.exe -help\" - show this message.

With no arguments, the window opens. In an interactive cmd prompt, use
\"start /wait simplewall.exe -install\" to read the exit code. Create simplewall.ini next to the
executable for a portable profile.xml. Otherwise settings are stored in
%ProgramData%\\simplewall-rust\\profile.xml.",
        ver = crate::model::APP_VERSION
    );
}
