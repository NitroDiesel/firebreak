//! Command line, same verbs as the C build:
//! `-install`, `-install -temp`, `-install -silent`, `-uninstall`, `-help`.

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
            eprintln!("Firebreak needs an elevated console to install filters.");
            return 1;
        }
        let mut profile = profile::load();
        if profile.apps.is_empty() {
            profile.apps = crate::apps::enumerate();
            let _ = profile::save(&profile);
        }
        profile.settings.filters_temporary = temp;
        return finish(wfp::install(&profile, temp));
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
Firebreak {ver}, based on simplewall by Henry++

\"firebreak.exe -install\" - enable filtering.
\"firebreak.exe -install -temp\" - enable filtering until reboot.
\"firebreak.exe -install -silent\" - enable filtering without prompt.
\"firebreak.exe -uninstall\" - remove all installed filters.
\"firebreak.exe -status\" - report whether the provider is installed.
\"firebreak.exe -help\" - show this message.

With no arguments, the window opens. In an interactive cmd prompt, use
\"start /wait firebreak.exe -install\" to read the exit code. Create firebreak.ini next to the
executable for a portable profile.xml. Otherwise settings are stored in
%ProgramData%\\Firebreak\\profile.xml.",
        ver = crate::model::APP_VERSION
    );
}
