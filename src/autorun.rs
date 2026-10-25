//! "Load on system startup" and "Skip UAC warning", both through Task Scheduler
//! tasks with "Run with highest privileges", as the C build does. An elevated
//! program in the Run key would prompt for UAC at every sign-in; a task does not.

use std::os::windows::process::CommandExt;
use std::process::Command;

/// Starts simplewall in the tray at sign-in.
const AUTORUN_TASK: &str = "simplewall-rust";
/// No trigger. A non-elevated launch runs it to get an elevated copy without a prompt.
const SKIP_UAC_TASK: &str = "simplewall-rust-skipuac";
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

pub fn autorun_enabled() -> bool {
    task_exists(AUTORUN_TASK)
}

pub fn set_autorun(on: bool) -> Result<(), String> {
    if on {
        create_task(AUTORUN_TASK, true, crate::MINIMIZED_FLAG)
    } else {
        delete_task(AUTORUN_TASK)
    }
}

pub fn skip_uac_enabled() -> bool {
    task_exists(SKIP_UAC_TASK)
}

pub fn set_skip_uac(on: bool) -> Result<(), String> {
    if on {
        create_task(SKIP_UAC_TASK, false, crate::ELEVATED_FLAG)
    } else {
        delete_task(SKIP_UAC_TASK)
    }
}

/// Start the elevated copy through the skip-UAC task. True when it started.
pub fn run_skip_uac() -> bool {
    task_exists(SKIP_UAC_TASK) && schtasks(&["/Run", "/TN", SKIP_UAC_TASK]).is_ok()
}

fn task_exists(name: &str) -> bool {
    schtasks(&["/Query", "/TN", name]).is_ok()
}

fn delete_task(name: &str) -> Result<(), String> {
    if !task_exists(name) {
        return Ok(());
    }
    schtasks(&["/Delete", "/TN", name, "/F"])
}

fn create_task(name: &str, at_logon: bool, args: &str) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let dir = exe.parent().map(|d| d.to_string_lossy().into_owned()).unwrap_or_default();
    let user = match (std::env::var("USERDOMAIN"), std::env::var("USERNAME")) {
        (Ok(domain), Ok(name)) => format!("{domain}\\{name}"),
        (_, Ok(name)) => name,
        _ => return Err("Could not determine the current user.".into()),
    };
    let xml = task_xml(&exe.to_string_lossy(), args, &dir, &user, at_logon);
    let path = std::env::temp_dir().join(format!("{name}.xml"));
    // Task Scheduler expects UTF-16 with a byte order mark.
    let mut bytes = vec![0xFF, 0xFE];
    bytes.extend(xml.encode_utf16().flat_map(u16::to_le_bytes));
    std::fs::write(&path, bytes).map_err(|e| e.to_string())?;
    let result = schtasks(&["/Create", "/TN", name, "/XML", &path.to_string_lossy(), "/F"]);
    let _ = std::fs::remove_file(&path);
    result
}

fn task_xml(exe: &str, args: &str, dir: &str, user: &str, at_logon: bool) -> String {
    let esc = |s: &str| {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
    };
    let triggers = if at_logon {
        format!("<LogonTrigger><Enabled>true</Enabled><UserId>{}</UserId></LogonTrigger>", esc(user))
    } else {
        String::new()
    };
    format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>simplewall</Description></RegistrationInfo>
  <Triggers>{triggers}</Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{user}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <AllowHardTerminate>false</AllowHardTerminate>
    <Priority>5</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{exe}</Command>
      <Arguments>{args}</Arguments>
      <WorkingDirectory>{dir}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"#,
        user = esc(user),
        exe = esc(exe),
        args = esc(args),
        dir = esc(dir),
    )
}

fn schtasks(args: &[&str]) -> Result<(), String> {
    let output = Command::new("schtasks.exe")
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| e.to_string())?;
    if output.status.success() {
        Ok(())
    } else {
        let err = String::from_utf8_lossy(&output.stderr).trim().to_string();
        Err(if err.is_empty() { format!("schtasks {} failed", args[0]) } else { err })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_xml_escapes_and_picks_trigger() {
        let xml = task_xml(r"C:\A & B\simplewall.exe", "-minimized", r"C:\A & B", r"PC\me", true);
        assert!(xml.contains(r"<Command>C:\A &amp; B\simplewall.exe</Command>"));
        assert!(xml.contains("<LogonTrigger>"));
        assert!(xml.contains("<RunLevel>HighestAvailable</RunLevel>"));
        assert!(!task_xml("x", "", "", "u", false).contains("<LogonTrigger>"));
    }

    /// Creates and deletes both real tasks. Needs an elevated console:
    /// `cargo test autorun -- --ignored`.
    #[test]
    #[ignore]
    fn creates_and_removes_tasks() {
        for (set, enabled) in [(set_autorun as fn(bool) -> _, autorun_enabled as fn() -> _), (set_skip_uac, skip_uac_enabled)] {
            set(true).unwrap();
            assert!(enabled());
            set(false).unwrap();
            assert!(!enabled());
        }
    }
}
