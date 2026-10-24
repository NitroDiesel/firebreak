# simplewall (Rust)

Rust port of [simplewall](https://github.com/henrypp/simplewall) 3.9.1 by Henry++.
The original program is GPL-3.0. This port is GPL-3.0 as well. See `LICENSE`.

![simplewall window](images/simplewall.png)

simplewall configures the Windows Filtering Platform. It does not talk to the Windows Firewall service.
Filters use the original provider `B0D553E2-C6A0-4A9A-AEB8-C752483ED62F` and sublayer `9FEE6F59-B951-4F9A-B52F-133DCF7A4279`. **Disable filtering** removes filters owned by that provider.
## Build

```
cargo build --release
```

The binary is `target\release\simplewall.exe`. Opening the window asks for elevation, the same as the original, because filters can only be installed or removed by an administrator. If the prompt is declined, the window still opens, but filters cannot be changed. The exe is a Windows GUI program, so no console window appears.

## Command line

```
simplewall.exe -install
simplewall.exe -install -temp
simplewall.exe -install -silent
simplewall.exe -uninstall
simplewall.exe -status
simplewall.exe -help
```

No arguments opens the window. The command line needs an elevated console, and output goes to the console it was started from. An interactive `cmd` prompt does not wait for GUI programs, so use `start /wait simplewall.exe -install` to read `%ERRORLEVEL%`. Batch files and redirected output wait as usual.

## Window

The layout follows the original: a menu bar (File, Edit, View, Settings, Blocklist, Help), a toolbar, and the search box on the right. Below are the tabs Apps, Services, UWP apps, Blocklist, System rules, User rules, Connections, and Packets log. Each tab is a grouped list, and the status bar shows filter state, unused apps, and apps with a timer.

- Toolbar buttons, left to right:
  - Enable or disable filtering. It asks first, and also offers "Until reboot".
  - Create rule.
  - Log to file, and log to UI (the Packets log).
  - Refresh.
  - Settings.
  - Show log, and clear log.
- Lists are grouped the same way as the original:
  - Apps: "Apps with internet access", "Apps with timer", "Apps with user rules", "Apps without internet access".
  - Rules: "Enabled rules [for all]", "Enabled rules [for apps]", "Disabled rules".
  - Click a column header to sort. Click a group header to collapse it.
- Rows use the original highlight colors:
  - Yellow: the rule applies to specific apps.
  - Red: the file is missing, or the rule has a syntax error.
  - Blue: a system app.
  - Gray: a pinned app.
- Double-click or Enter opens the rule editor or the app properties. Right-click has timers, pin, open file location, copy, and delete.
- Keyboard shortcuts:

  | Keys | Action |
  | --- | --- |
  | Ctrl+F | Search |
  | F5 | Refresh |
  | F2 | Settings |
  | F1 | About |
  | Ctrl+Tab, Ctrl+Shift+Tab | Next or previous tab |
  | Space | Check or uncheck the row |
  | Del | Delete |
  | Ctrl+C | Copy |
  | Ctrl+E | Open file location |
  | Ctrl+Shift+X | Purge unused apps |
  | Ctrl+Shift+T | Purge timers |
- Search matches a substring. Start it with `re:` to search with a regular expression.
- The accent color follows the Windows accent color. The font is Segoe UI.

Filter installs run on a background thread, so the window does not freeze while 1,500 blocklist rules are applied.

## Filtering

Checked apps are permitted. A lowest-weight block filter drops every other ALE connect and receive. Loopback and IPv6 neighbor discovery are permitted by default. This executable is always permitted, so the program can still remove its own filters. Internal system, blocklist, and custom rules are loaded from `resources/profile_internal.xml` (the upstream file).

- Each app is matched the way the original matches it:
  - Services: the service SID.
  - UWP apps: the package SID.
  - Kernel traffic: the `System` app id.
- Blocklist groups each have Disable, Allow, or Block, from the Blocklist menu or Settings:
  - Microsoft spying and telemetry. Default: Block.
  - Microsoft update. Default: Disable.
  - Microsoft applications. Default: Disable.
- "Until reboot" filters are not persistent. They stay installed until Windows restarts.
- Timers allow an app until the time runs out, then block it again.
- The Packets log reads dropped connections from the WFP net event buffer. It lists only drops caused by simplewall's own filters.

User and custom allow rules sit above the blocklist. To let a blocklist entry win, turn off "User rules take priority over the blocklist". "Allow local network (LAN)" permits private, link-local, and multicast ranges.

Create `simplewall.ini` next to the executable to store `profile.xml` in that folder. Otherwise the profile is `%ProgramData%\simplewall-rust\profile.xml`, which still exists after reboot when Administrator Protection isolates the elevated account. If the ProgramData file is not there yet, an older `%APPDATA%\simplewall-rust\profile.xml` is read once.

The installer and portable zip are built on GitHub by the `release` workflow, not on a workstation. Run that workflow, or push a `v*` tag. The assets are attached to the GitHub release.

## What this port covers

| C module | Rust |
| --- | --- |
| `wfp.c`: provider, sublayer, loopback, IPv6 bootstrap, app permits, block-all, transactions, net events | `src/wfp.rs` |
| `db.c` / `profile.c`: internal rules, blocklist states, the user profile | `src/profile.rs` |
| Rule syntax from the readme | `src/rules.rs` |
| `network.c`: endpoint tables | `src/log.rs` |
| Process, service, and UWP package inventory | `src/apps.rs` |
| `main.c`: command line | `src/cli.rs` |
| Win32 dialogs and list views | `src/ui/` (egui) |

Not carried over: the tray icon, notification popups, encrypted `SWC` profiles, silent-drop callouts, file signature checks, and the donate button.
