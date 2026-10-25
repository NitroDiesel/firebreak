# simplewall (Rust)

Rust port of [simplewall](https://github.com/henrypp/simplewall) 3.9.2 by Henry++.
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
  - Notifications, log to file, and log to UI (the Packets log).
  - Refresh, and Settings.
  - Show log, and clear log.
- Lists are grouped the same way as the original:
  - Apps: "Apps with internet access", "Apps with timer", "Apps with user rules", "Apps without internet access".
  - Rules: "Enabled rules [for all]", "Enabled rules [for apps]", "Disabled rules".
  - Click a column header to sort. Click a group header to collapse it.
- Rows use the original highlight colors, each of which can be turned off in Settings > Appearance:
  - Red: the file is missing, or the rule has a syntax error.
  - Pink: the app has an active connection.
  - Green: the app is digitally signed.
  - Yellow: the rule applies to specific apps.
  - Gray: a pinned app.
  - Blue: a system app or service.
- Double-click or Enter opens the rule editor or the app properties. Right-click has timers, pin, open containing folder, copy, and delete.
- Deleting an app or a user rule asks first. There is no undo.
- Dialogs keep keyboard focus inside them and close with Escape. In a small window their content scrolls and the buttons stay in view.
- Tab moves between controls and draws a focus ring around the current one. The arrow keys move through the list.
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
  | Ctrl+E | Open containing folder |
  | Ctrl+I | Show log |
  | Ctrl+X | Clear log (asks first) |
  | Ctrl+Shift+X | Purge unused apps (asks first) |
  | Ctrl+Shift+T | Purge timers |
- Search matches a substring. Start it with `re:` to search with a regular expression.
- The View menu has the original's options:
  - Always on top, dark theme, and show filenames only.
  - Autosize columns, to fit each column to its contents.
  - Show search bar. Ctrl+F shows it again.
  - Details, Icons, or Tiles view, with small, large, or extra-large icons. "Do not load icons" skips reading app icons.
  - Language, and Font..., which picks the window's font and size.
- The theme is dark, light, or the same as Windows. The accent color follows the Windows accent color. In the light theme a pale accent is darkened where it is text or a line, so it stays readable.
- Animations follow Windows' "Animation effects" setting.
- Errors in the status bar stay until you click them. Hover over a cut-off cell or message to read all of it.
- The window is in the original's 29 languages (Settings > General > Language), from its language file. Labels worded as in the original are translated; wording new to this port stays English.
- The last tab, sort order, and window size are kept for next time.

Filter installs run on a background thread, so the window does not freeze while 1,500 blocklist rules are applied.

## Tray and notifications

- simplewall has a tray icon, with the original's menu: Show/Hide, Enable or Disable filters, Notifications, Packets log, Settings, Website, About, and Exit. The icon shows whether filters are on.
- Minimizing sends the window to the tray. A second launch brings the running window back.
- Exiting while filters are on asks first. Filters keep working after simplewall exits.
- When an app that is not allowed tries to connect, a notification appears in the middle of the screen. It shows the app, its signer, the address, host name, port, protocol, and time, with Allow, Allow for a set time, Block, and a menu with Create rule, Open containing folder, Kill process, and Disable notifications for this app. Block stops further notifications for that app. The same app waits 60 seconds between notifications, and the sound is skipped while a full-screen app is in front.
- Apps seen in blocked connections are added to the list automatically.
- Settings > General has Load on system startup, Start minimized, and Skip UAC warning. The two startup options use Task Scheduler with highest privileges, so no UAC prompt appears.

## Filtering

Checked apps are permitted. A lowest-weight block filter drops every other ALE connect and receive. This executable is always permitted, so the program can still remove its own filters. Internal system, blocklist, and custom rules are loaded from `resources/profile_internal.xml` (the upstream file).

- Each app is matched the way the original matches it:
  - Services: the service SID.
  - UWP apps: the package SID.
  - Kernel traffic: the `System` app id.
- Settings > Filters has the original's options:
  - Allow loopback, IPv6 (6to4 and neighbor discovery), and local network (LAN).
  - Block outbound and block inbound connections. Both are on by default.
  - Stealth mode, on by default: port scans get no reply.
  - Boot-time filters, on by default: filtering starts before the filter engine loads at boot. Allow IP forwarding keeps Mobile Hotspot and Internet Connection Sharing working.
  - Disable internal rules, to install only your own.
- Blocklist groups each have Disable, Allow, or Block, from the Blocklist menu or Settings:
  - Microsoft spying and telemetry. Default: Block.
  - Microsoft update. Default: Disable.
  - Microsoft applications. Default: Disable.
- Apps can be assigned to the built-in system rules in the rule editor, as in the original.
- Allow Windows Update (Settings menu or Settings > Filters) is the original's Windows Update fix. The Windows Update services run from a copy of svchost.exe named `wusvc.exe`, and that copy is allowed, so updates work while every other svchost.exe service stays blocked.
- "Until reboot" filters are not persistent. They stay installed until Windows restarts.
- Timers allow an app until the time runs out, then block it again. Turning a timer off also blocks the app. Timers only count down while simplewall runs; it can sit in the tray. Exiting with timers running asks to end them first.
- Per-user service instances (such as `CDPUserSvc_1a2b3`) get a new name at every sign-in, so they are not listed. Allow `svchost.exe` to cover them.

User and custom allow rules sit above the blocklist. To let a blocklist entry win, turn off "User rules take priority over the blocklist".

## Security checks

- Digital signatures are checked for every app, through the file's own signature or the Windows catalog. The signer shows in the tooltip and in notifications. Online revocation checks are optional.
- With "Check apps for sha-256 hash" on, an allowed app is blocked again if its file changes on disk. It is checked every 10 minutes.

## Connections and logs

- The Connections tab refreshes every 2 seconds. It lists every TCP state and UDP endpoint, with host names for remote addresses, and optionally the connections of processes that have exited.
- When run as administrator, the Connections tab shows each connection's download and upload speed and its total traffic. TCP is always measured. UDP and QUIC are measured with "Measure UDP/QUIC traffic" in Settings, through a kernel network trace.
- The Packets log updates live with connections simplewall blocked.
- Log to file writes the original's CSV columns to `%USERPROFILE%\simplewall.csv`. The file starts over at a size limit (1 MB by default). Port scans blocked by stealth mode are left out of both logs unless you turn that off.

## Profile

Create `simplewall.ini` next to the executable to store `profile.xml` in that folder. Otherwise the profile is `%ProgramData%\simplewall-rust\profile.xml`, which still exists after reboot when Administrator Protection isolates the elevated account. If the ProgramData file is not there yet, an older `%APPDATA%\simplewall-rust\profile.xml` is read once.

- The first run imports the original simplewall's profile from `%APPDATA%\Henry++\simplewall\profile.xml`, if there is one.
- File > Import reads this port's profile or the original's, plain, compressed, or encrypted. File > Export saves the profile anywhere.
- Settings > Profile type saves the profile as plain XML, compressed, or encrypted, in the original's formats.
- A day-old copy is kept as `profile.xml.bak`, and is used if the profile cannot be read.

## Releases

Releases have three assets, all built on GitHub by the `release` workflow, not on a workstation:

- `simplewall-<version>-setup.exe`: the NSIS installer.
- `simplewall-<version>-setup.msi`: the Windows Installer package. Use it for Group Policy or Intune, or silently with `msiexec /i simplewall-<version>-setup.msi /qn`. A newer MSI upgrades an older one in place.
- `simplewall-<version>-bin.zip`: the portable build.

Install with one installer, not both; they use the same folder. Uninstalling leaves filters installed, so turn filtering off first. To publish, push a `v*` tag, or run the workflow, which takes the version from `Cargo.toml`. simplewall checks for a newer release once a day, and Help > Check for updates checks right away.

## What this port covers

| C module | Rust |
| --- | --- |
| `wfp.c`: provider, sublayer, global filters (loopback, IPv6, stealth, boot-time, block-all), app permits, rules, transactions | `src/wfp.rs` |
| `log.c`: net event subscription, packets log, log file | `src/netevents.rs`, `src/ui/mod.rs` |
| `notifications.c`: notification window | `src/ui/notify.rs` |
| `db.c` / `profile.c`: internal rules, blocklist states, the user profile, SWC decoding | `src/profile.rs`, `src/swc.rs` |
| `helper.c`: signatures and file hashes | `src/security.rs` |
| `network.c`: connection monitor | `src/log.rs`, `src/ui/monitor.rs` |
| Rule syntax from the readme | `src/rules.rs` |
| Process, service, and UWP package inventory | `src/apps.rs` |
| Tray icon | `src/tray.rs` |
| Autorun and skip UAC | `src/autorun.rs` |
| Update check | `src/update.rs` |
| Language files | `src/i18n.rs` |
| `main.c`: command line | `src/cli.rs` |
| Win32 dialogs and list views | `src/ui/` (egui) |

Not carried over:

- The donate button.
