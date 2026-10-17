# simplewall (Rust)

Rust port of [simplewall](https://github.com/henrypp/simplewall) 3.9.1 by Henry++.
The original program is GPL-3.0. This port is GPL-3.0 as well. See `LICENSE`.

simplewall configures the Windows Filtering Platform. It does not talk to the Windows Firewall service.
Filters use the original provider `B0D553E2-C6A0-4A9A-AEB8-C752483ED62F` and sublayer `9FEE6F59-B951-4F9A-B52F-133DCF7A4279`. **Disable filters** removes filters owned by that provider.

## Build

```
cargo build --release
```

The binary is `target\release\simplewall.exe`. It must be elevated to install or remove filters.

## Command line

```
simplewall.exe -install
simplewall.exe -install -temp
simplewall.exe -install -silent
simplewall.exe -uninstall
simplewall.exe -status
simplewall.exe -help
```

No arguments opens the window.

Checked apps are permitted. A lowest-weight block filter drops every other ALE connect and receive. Loopback and IPv6 neighbor discovery are permitted by default. This executable is always permitted, so the program can still remove its own filters. Internal system, blocklist, and custom rules are loaded from `resources/profile_internal.xml` (the upstream file).

User and custom allow rules sit above the blocklist. Turn that off with "User allows beat blocklist" if a blocklist entry must win. "Allow LAN" permits private, link-local, and multicast ranges. Search accepts a substring, a `re:` prefix, or the Regex checkbox. Pin keeps an app at the top of the list. The comment field is stored on the app.

Create `simplewall.ini` next to the executable to store `profile.xml` in that folder. Otherwise the profile is `%ProgramData%\simplewall-rust\profile.xml`, which still exists after reboot when Administrator Protection isolates the elevated account. An older `%APPDATA%\simplewall-rust\profile.xml` is read once if the ProgramData file is not there yet.

Installer and portable zip are built on GitHub by the `release` workflow, not on a workstation. Run that workflow, or push a `v*` tag. The assets are attached to the GitHub release.

## What this port covers

| C module | Rust |
| --- | --- |
| `wfp.c` provider, sublayer, loopback, IPv6 bootstrap, app permits, block-all, transactions | `src/wfp.rs` |
| `db.c` internal rules and the user profile | `src/profile.rs` |
| rule syntax in the readme | `src/rules.rs` |
| `network.c` / `udpstats.c` endpoint tables | `src/log.rs` |
| process and service inventory | `src/apps.rs` |
| `main.c` command line | `src/cli.rs` |
| Win32 dialogs | `src/ui.rs` (egui) |

Not carried over one-for-one: the Win32 dialog templates, tray icon, notification popups, encrypted `SWC` profiles, silent-drop callouts, and per-service SID filters. Service names in internal rules are resolved to the service image path. A rule with only `is_services` and no image applies to every app.
