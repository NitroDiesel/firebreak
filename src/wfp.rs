//! Windows Filtering Platform engine.
//!
//! Provider `B0D553E2-...` and sublayer `9FEE6F59-...` match `src/wfp.h`, so
//! Disable filters removes filters this port (and the original simplewall)
//! installed under that provider.
//!
//! Install is explicit. Nothing here runs during `cargo test`.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::*;
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    ConvertStringSidToSidW, SDDL_REVISION_1,
};
use windows::Win32::Security::{
    GetTokenInformation, LookupAccountNameW, TokenElevation, PSECURITY_DESCRIPTOR, PSID, SID, SID_NAME_USE,
    TOKEN_ELEVATION, TOKEN_QUERY,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::apps::{expand_env, wide};
use crate::model::{AppItem, AppKind, Direction, Profile, Rule, RuleAction, RuleOrigin, APP_NAME, SYSTEM_APP};
use crate::rules::{self, PortSpec, Token};

const AUTH_WINNT: u32 = 10;
const WEIGHT_IMPORTANT: u8 = 0x0F;
/// Above the blocklist, so a user allow can punch through it (issue 2073).
const WEIGHT_USER_OVERRIDE: u8 = 0x0E;
const WEIGHT_BLOCKLIST: u8 = 0x0D;
const WEIGHT_USER_BLOCK: u8 = 0x0C;
const WEIGHT_USER: u8 = 0x0B;
const WEIGHT_SYSTEM: u8 = 0x0A;
const WEIGHT_APP: u8 = 0x09;
const WEIGHT_LOWEST: u8 = 0x08;
/// `FWPM_CONDITION_ICMP_TYPE` is a `#define` for the local port field in fwpmu.h.
const ICMP_TYPE: windows::core::GUID = FWPM_CONDITION_IP_LOCAL_PORT;
/// `FWP_ACTRL_MATCH_FILTER`: the right a service SID descriptor grants.
const MATCH_FILTER: u32 = 0x1;
/// Cap per rule, so one huge rule cannot flood the engine.
const MAX_FILTERS_PER_RULE: u32 = 128;
const FILETIME_UNIX_EPOCH: u64 = 116_444_736_000_000_000;

fn win(code: u32, what: &str) -> Result<(), String> {
    if code == 0 {
        Ok(())
    } else {
        Err(format!("{what} failed (0x{code:08X})"))
    }
}

pub fn is_admin() -> bool {
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION::default();
        let mut size = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut size,
        );
        let _ = CloseHandle(token);
        ok.is_ok() && elevation.TokenIsElevated != 0
    }
}

pub fn filters_installed() -> Result<bool, String> {
    let engine = Engine::open()?;
    Ok(unsafe { provider_present(engine.handle) })
}

pub fn install(profile: &Profile, temporary: bool) -> Result<String, String> {
    if !is_admin() {
        return Err("Administrator rights are required to change filters.".into());
    }
    let engine = Engine::open()?;
    let skipped = unsafe {
        transact(engine.handle, true)?;
        let result = (|| {
            remove_owned(engine.handle)?;
            add_provider(engine.handle, !temporary)?;
            add_sublayer(engine.handle, !temporary)?;
            if profile.settings.allow_loopback {
                add_loopback(engine.handle, !temporary)?;
            }
            if profile.settings.allow_ipv6 {
                add_ipv6_bootstrap(engine.handle, !temporary)?;
            }
            if profile.settings.allow_lan {
                add_lan(engine.handle, !temporary)?;
            }
            let skipped = add_rules(engine.handle, profile, !temporary)?;
            add_apps(engine.handle, profile, !temporary)?;
            add_self(engine.handle, !temporary)?;
            add_block_all(engine.handle, !temporary)?;
            Ok(skipped)
        })();
        let skipped = match result {
            Ok(skipped) => skipped,
            Err(err) => {
                let _ = FwpmTransactionAbort0(engine.handle);
                return Err(err);
            }
        };
        transact(engine.handle, false)?;
        let _ = set_collect(engine.handle, profile.settings.log_ui);
        skipped
    };
    let mut msg = if temporary {
        "Filters are enabled until reboot.".to_string()
    } else {
        "Filters are enabled.".to_string()
    };
    if !skipped.is_empty() {
        msg.push_str(&format!(" Skipped rules with a syntax error: {}.", skipped.join(", ")));
    }
    Ok(msg)
}

pub fn uninstall() -> Result<String, String> {
    if !is_admin() {
        return Err("Administrator rights are required to change filters.".into());
    }
    let engine = Engine::open()?;
    unsafe {
        // A failed transaction used to leave the provider in place (issue 2129).
        // Delete once inside a transaction, then again outside it if anything remains.
        if transact(engine.handle, true).is_ok() {
            let inside = remove_owned(engine.handle);
            if inside.is_err() {
                let _ = FwpmTransactionAbort0(engine.handle);
            } else if let Err(err) = transact(engine.handle, false) {
                let _ = FwpmTransactionAbort0(engine.handle);
                return Err(err);
            }
        }
        remove_owned(engine.handle)?;
        if provider_present(engine.handle) {
            return Err("Filters were not fully removed. Run -uninstall again as administrator.".into());
        }
    }
    Ok("Filters are disabled!".into())
}

struct Engine {
    handle: HANDLE,
}

impl Engine {
    /// A dynamic session would delete "until reboot" filters as soon as the handle
    /// closes. Temporary filters are simply added without the persistent flag.
    fn open() -> Result<Self, String> {
        unsafe {
            let name = wide(APP_NAME);
            let desc = wide("simplewall rust session");
            let session = FWPM_SESSION0 {
                displayData: FWPM_DISPLAY_DATA0 {
                    name: PWSTR(name.as_ptr() as *mut _),
                    description: PWSTR(desc.as_ptr() as *mut _),
                },
                ..Default::default()
            };
            let mut handle = HANDLE::default();
            win(
                FwpmEngineOpen0(PCWSTR::null(), AUTH_WINNT, None, Some(&session), &mut handle),
                "FwpmEngineOpen0",
            )?;
            Ok(Self { handle })
        }
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        unsafe {
            if !self.handle.is_invalid() {
                let _ = FwpmEngineClose0(self.handle);
            }
        }
    }
}

unsafe fn transact(engine: HANDLE, begin: bool) -> Result<(), String> {
    if begin {
        win(FwpmTransactionBegin0(engine, 0), "transaction begin")
    } else {
        win(FwpmTransactionCommit0(engine), "transaction commit")
    }
}

fn provider_guid() -> windows::core::GUID {
    windows::core::GUID::from_u128(0xB0D553E2_C6A0_4A9A_AEB8_C752483ED62F)
}

fn sublayer_guid() -> windows::core::GUID {
    windows::core::GUID::from_u128(0x9FEE6F59_B951_4F9A_B52F_133DCF7A4279)
}

unsafe fn provider_present(engine: HANDLE) -> bool {
    let mut ptr = std::ptr::null_mut();
    let ok = FwpmProviderGetByKey0(engine, &provider_guid(), &mut ptr);
    if ok == 0 && !ptr.is_null() {
        FwpmFreeMemory0(&mut ptr as *mut _ as *mut *mut _);
        true
    } else {
        false
    }
}

unsafe fn remove_owned(engine: HANDLE) -> Result<(), String> {
    let mut keys = Vec::new();
    let mut template = FWPM_FILTER_ENUM_TEMPLATE0::default();
    let mut provider = provider_guid();
    template.providerKey = &mut provider;
    let mut enum_handle = HANDLE::default();
    if FwpmFilterCreateEnumHandle0(engine, Some(&template), &mut enum_handle) == 0 {
        loop {
            let mut entries = std::ptr::null_mut();
            let mut returned = 0u32;
            if FwpmFilterEnum0(engine, enum_handle, 128, &mut entries, &mut returned) != 0
                || returned == 0
                || entries.is_null()
            {
                break;
            }
            for i in 0..returned as usize {
                let filter = *entries.add(i);
                if !filter.is_null() {
                    keys.push((*filter).filterKey);
                }
            }
            FwpmFreeMemory0(&mut entries as *mut _ as *mut *mut _);
        }
        let _ = FwpmFilterDestroyEnumHandle0(engine, enum_handle);
    }
    for key in keys {
        let _ = FwpmFilterDeleteByKey0(engine, &key);
    }
    let _ = FwpmSubLayerDeleteByKey0(engine, &sublayer_guid());
    let _ = FwpmProviderDeleteByKey0(engine, &provider_guid());
    Ok(())
}

unsafe fn add_provider(engine: HANDLE, persistent: bool) -> Result<(), String> {
    let name = wide("simplewall");
    let desc = wide("simplewall rust WFP provider");
    let mut provider = FWPM_PROVIDER0 {
        providerKey: provider_guid(),
        displayData: FWPM_DISPLAY_DATA0 {
            name: PWSTR(name.as_ptr() as *mut _),
            description: PWSTR(desc.as_ptr() as *mut _),
        },
        flags: if persistent { FWPM_PROVIDER_FLAG_PERSISTENT } else { 0 },
        ..Default::default()
    };
    win(FwpmProviderAdd0(engine, &mut provider, None), "provider add")
}

unsafe fn add_sublayer(engine: HANDLE, persistent: bool) -> Result<(), String> {
    let name = wide("simplewall");
    let desc = wide("simplewall rust sublayer");
    let mut provider = provider_guid();
    let mut layer = FWPM_SUBLAYER0 {
        subLayerKey: sublayer_guid(),
        displayData: FWPM_DISPLAY_DATA0 {
            name: PWSTR(name.as_ptr() as *mut _),
            description: PWSTR(desc.as_ptr() as *mut _),
        },
        flags: if persistent { FWPM_SUBLAYER_FLAG_PERSISTENT } else { 0 },
        providerKey: &mut provider,
        weight: 0xFFFF,
        ..Default::default()
    };
    win(FwpmSubLayerAdd0(engine, &mut layer, None), "sublayer add")
}

/// Loopback and app-container loopback, as the C build does on Windows 8 and later.
unsafe fn add_loopback(engine: HANDLE, persistent: bool) -> Result<(), String> {
    let mut cond = FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_FLAGS,
        matchType: FWP_MATCH_FLAGS_ANY_SET,
        ..Default::default()
    };
    cond.conditionValue.r#type = FWP_UINT32;
    cond.conditionValue.Anonymous.uint32 =
        FWP_CONDITION_FLAG_IS_LOOPBACK | FWP_CONDITION_FLAG_IS_APPCONTAINER_LOOPBACK;
    for layer in connect_and_accept() {
        add_filter(engine, "AllowLoopback", layer, WEIGHT_IMPORTANT, true, persistent, &mut [cond])?;
    }
    Ok(())
}

unsafe fn add_ipv6_bootstrap(engine: HANDLE, persistent: bool) -> Result<(), String> {
    let mut proto = condition_u8(FWPM_CONDITION_IP_PROTOCOL, 41);
    add_filter(
        engine,
        "Allow6to4",
        FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
        WEIGHT_IMPORTANT,
        true,
        persistent,
        std::slice::from_mut(&mut proto),
    )?;
    // Router and neighbor solicitation and advertisement (types 133 to 136).
    for icmp in [0x85u16, 0x86, 0x87, 0x88] {
        let mut cond = condition_u16(ICMP_TYPE, icmp);
        add_filter(
            engine,
            &format!("AllowIcmpV6Type{icmp}"),
            FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
            WEIGHT_IMPORTANT,
            true,
            persistent,
            std::slice::from_mut(&mut cond),
        )?;
    }
    Ok(())
}

unsafe fn add_block_all(engine: HANDLE, persistent: bool) -> Result<(), String> {
    for layer in connect_and_accept() {
        add_filter(engine, "BlockConnection", layer, WEIGHT_LOWEST, false, persistent, &mut [])?;
    }
    Ok(())
}

unsafe fn add_self(engine: HANDLE, persistent: bool) -> Result<(), String> {
    let Ok(path) = std::env::current_exe() else {
        return Ok(());
    };
    if let Some(id) = AppId::file(&path.to_string_lossy()) {
        add_app_permit(engine, "simplewall", &id, persistent)?;
    }
    Ok(())
}

unsafe fn add_lan(engine: HANDLE, persistent: bool) -> Result<(), String> {
    let rule = Rule {
        name: "AllowLan".into(),
        remote: "10.0.0.0/8;172.16.0.0/12;192.168.0.0/16;169.254.0.0/16;224.0.0.0/4;[fc00::]/7;[fe80::]/10;[ff00::]/8".into(),
        local: String::new(),
        direction: Direction::Any,
        action: RuleAction::Permit,
        protocol: 0,
        enabled: true,
        origin: RuleOrigin::System,
        apps: Vec::new(),
        services: false,
        kernel: false,
        readonly: true,
    };
    add_one_rule(engine, &rule, persistent, WEIGHT_IMPORTANT).map(|_| ())
}

unsafe fn add_apps(engine: HANDLE, profile: &Profile, persistent: bool) -> Result<(), String> {
    for app in profile.apps.iter().filter(|app| app.allowed_now()) {
        // An app that no longer resolves (deleted file, removed service) is skipped.
        if let Some(id) = AppId::for_app(app) {
            add_app_permit(engine, &app.display_name, &id, persistent)?;
        }
    }
    Ok(())
}

unsafe fn add_app_permit(engine: HANDLE, name: &str, id: &AppId, persistent: bool) -> Result<(), String> {
    let mut cond = id.condition();
    for layer in connect_and_accept() {
        add_filter(engine, name, layer, WEIGHT_APP, true, persistent, std::slice::from_mut(&mut cond))?;
    }
    Ok(())
}

/// Returns the names of rules that were skipped because their text does not parse.
unsafe fn add_rules(engine: HANDLE, profile: &Profile, persistent: bool) -> Result<Vec<String>, String> {
    let mut skipped = Vec::new();
    for rule in profile.rules.iter().filter(|rule| rule.enabled) {
        let weight = rule_weight(rule, profile.settings.user_allows_override_blocklist);
        if !add_one_rule(engine, rule, persistent, weight)? {
            skipped.push(rule.name.clone());
        }
    }
    Ok(skipped)
}

pub(crate) fn rule_weight(rule: &Rule, user_allows_override_blocklist: bool) -> u8 {
    match (rule.action, rule.origin) {
        (RuleAction::Permit, RuleOrigin::User | RuleOrigin::Custom)
            if user_allows_override_blocklist =>
        {
            WEIGHT_USER_OVERRIDE
        }
        (RuleAction::Block, RuleOrigin::Blocklist) => WEIGHT_BLOCKLIST,
        (RuleAction::Block, _) => WEIGHT_USER_BLOCK,
        (_, RuleOrigin::System) => WEIGHT_SYSTEM,
        _ => WEIGHT_USER,
    }
}

/// False when the rule text does not parse. A rule that failed to parse
/// used to install with no address condition, which matched every address.
unsafe fn add_one_rule(engine: HANDLE, rule: &Rule, persistent: bool, weight: u8) -> Result<bool, String> {
    let (Ok(remote), Ok(local)) = (
        rules::parse_rule_list(&rule.remote),
        rules::parse_rule_list(&rule.local),
    ) else {
        return Ok(false);
    };
    let permit = rule.action == RuleAction::Permit;
    for target in rule_targets(rule) {
        match target {
            Target::All => emit_rule_filters(engine, rule, weight, permit, persistent, None, &remote, &local)?,
            Target::App(id) => {
                emit_rule_filters(engine, rule, weight, permit, persistent, Some(&id), &remote, &local)?
            }
            // The app is not on this machine. Skip it; never widen to every app.
            Target::Missing => {}
        }
    }
    Ok(true)
}

enum Target {
    All,
    App(AppId),
    Missing,
}

/// Same targets as `_wfp_create4filters`: no apps means every app; otherwise
/// the kernel ("System"), the service host, and each listed app or service.
fn rule_targets(rule: &Rule) -> Vec<Target> {
    if rule.apps.is_empty() {
        return vec![Target::All];
    }
    let found = |id: Option<AppId>| id.map(Target::App).unwrap_or(Target::Missing);
    let mut targets = Vec::new();
    if rule.kernel {
        targets.push(Target::App(AppId::system()));
    }
    if rule.services {
        targets.push(found(AppId::file(&expand_env(r"%SystemRoot%\System32\svchost.exe"))));
    }
    for app in &rule.apps {
        let path = expand_env(app);
        targets.push(if path.eq_ignore_ascii_case(SYSTEM_APP) {
            Target::App(AppId::system())
        } else if path.contains('\\') || path.contains(':') {
            found(AppId::file(&path))
        } else if path.to_ascii_uppercase().starts_with("S-1-15-") {
            found(AppId::package(&path))
        } else {
            found(AppId::service(&path))
        });
    }
    targets
}

#[allow(clippy::too_many_arguments)]
unsafe fn emit_rule_filters(
    engine: HANDLE,
    rule: &Rule,
    weight: u8,
    permit: bool,
    persistent: bool,
    app: Option<&AppId>,
    remote: &[Token],
    local: &[Token],
) -> Result<(), String> {
    let remotes: Vec<Option<&Token>> = if remote.is_empty() {
        vec![None]
    } else {
        remote.iter().map(Some).collect()
    };
    let locals: Vec<Option<&Token>> = if local.is_empty() {
        vec![None]
    } else {
        local.iter().map(Some).collect()
    };
    let mut made = 0u32;
    for remote in &remotes {
        for local in &locals {
            if made >= MAX_FILTERS_PER_RULE {
                return Ok(());
            }
            emit_pair(engine, rule, weight, permit, persistent, app, *remote, *local)?;
            made += 1;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
unsafe fn emit_pair(
    engine: HANDLE,
    rule: &Rule,
    weight: u8,
    permit: bool,
    persistent: bool,
    app: Option<&AppId>,
    remote: Option<&Token>,
    local: Option<&Token>,
) -> Result<(), String> {
    let is_v6 = |t: Option<&Token>| matches!(t, Some(Token::V6 { .. }));
    let is_v4 = |t: Option<&Token>| matches!(t, Some(Token::V4 { .. } | Token::V4Range { .. }));
    let v6 = is_v6(remote) || is_v6(local);
    let v4 = is_v4(remote) || is_v4(local);
    let families: &[bool] = match (v4, v6) {
        // An IPv4 remote with an IPv6 local can never match. Dropping one side
        // would widen the filter, so skip the pair.
        (true, true) => return Ok(()),
        (true, false) => &[false],
        (false, true) => &[true],
        (false, false) => &[false, true],
    };
    for ipv6 in families {
        let connect = if *ipv6 { FWPM_LAYER_ALE_AUTH_CONNECT_V6 } else { FWPM_LAYER_ALE_AUTH_CONNECT_V4 };
        let accept = if *ipv6 { FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6 } else { FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4 };
        let layers: &[windows::core::GUID] = match rule.direction {
            Direction::Outbound => &[connect],
            Direction::Inbound => &[accept],
            Direction::Any => &[connect, accept],
        };
        for layer in layers {
            let mut storage = CondStore::default();
            let conds = storage.fill(rule.protocol, app, remote, local);
            // No condition at all would match every packet on the layer.
            if conds.is_empty() {
                continue;
            }
            add_filter(engine, &rule.name, *layer, weight, permit, persistent, conds)?;
        }
    }
    Ok(())
}

// Conditions hold raw pointers to these values, so each one is boxed and
// keeps its address when the Vec grows.
#[allow(clippy::vec_box)]
#[derive(Default)]
struct CondStore {
    conds: Vec<FWPM_FILTER_CONDITION0>,
    v4: Vec<Box<FWP_V4_ADDR_AND_MASK>>,
    v6: Vec<Box<FWP_V6_ADDR_AND_MASK>>,
    ranges: Vec<Box<FWP_RANGE0>>,
}

impl CondStore {
    /// "Remote" text maps to the remote fields on both connect and accept
    /// layers, as `_wfp_createrulefilter` does.
    fn fill(
        &mut self,
        protocol: u8,
        app: Option<&AppId>,
        remote: Option<&Token>,
        local: Option<&Token>,
    ) -> &mut [FWPM_FILTER_CONDITION0] {
        if protocol != 0 {
            self.conds.push(condition_u8(FWPM_CONDITION_IP_PROTOCOL, protocol));
        }
        if let Some(app) = app {
            self.conds.push(app.condition());
        }
        if let Some(token) = remote {
            self.push_token(token, false);
        }
        if let Some(token) = local {
            self.push_token(token, true);
        }
        &mut self.conds
    }

    fn push_token(&mut self, token: &Token, local: bool) {
        let (addr_key, port_key) = if local {
            (FWPM_CONDITION_IP_LOCAL_ADDRESS, FWPM_CONDITION_IP_LOCAL_PORT)
        } else {
            (FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_CONDITION_IP_REMOTE_PORT)
        };
        match token {
            Token::Port(p) => self.conds.push(condition_u16(port_key, *p)),
            Token::PortRange(a, b) => self.push_range(port_key, range_u16(*a, *b)),
            Token::V4 { addr, mask, port } => {
                let mut value = Box::new(FWP_V4_ADDR_AND_MASK { addr: *addr, mask: *mask });
                let mut cond = condition(addr_key, FWP_MATCH_EQUAL, FWP_V4_ADDR_MASK);
                cond.conditionValue.Anonymous.v4AddrMask = &mut *value;
                self.v4.push(value);
                self.conds.push(cond);
                self.push_port(port_key, port.as_ref());
            }
            Token::V4Range { start, end, port } => {
                self.push_range(addr_key, range_u32(*start, *end));
                self.push_port(port_key, port.as_ref());
            }
            Token::V6 { addr, prefix, port } => {
                let mut masked = *addr;
                for (b, m) in masked.iter_mut().zip(rules::v6_mask(*prefix)) {
                    *b &= m;
                }
                let mut value = Box::new(FWP_V6_ADDR_AND_MASK { addr: masked, prefixLength: *prefix });
                let mut cond = condition(addr_key, FWP_MATCH_EQUAL, FWP_V6_ADDR_MASK);
                cond.conditionValue.Anonymous.v6AddrMask = &mut *value;
                self.v6.push(value);
                self.conds.push(cond);
                self.push_port(port_key, port.as_ref());
            }
        }
    }

    fn push_port(&mut self, key: windows::core::GUID, port: Option<&PortSpec>) {
        match port {
            Some(PortSpec::One(p)) => self.conds.push(condition_u16(key, *p)),
            Some(PortSpec::Range(a, b)) => self.push_range(key, range_u16(*a, *b)),
            None => {}
        }
    }

    fn push_range(&mut self, key: windows::core::GUID, range: FWP_RANGE0) {
        let mut value = Box::new(range);
        let mut cond = condition(key, FWP_MATCH_RANGE, FWP_RANGE_TYPE);
        cond.conditionValue.Anonymous.rangeValue = &mut *value;
        self.ranges.push(value);
        self.conds.push(cond);
    }
}

/// One app condition, owning the memory the condition points at.
enum AppId {
    /// From `FwpmGetAppIdFromFileName0`.
    File(*mut FWP_BYTE_BLOB),
    /// The literal "System", which is how WFP names kernel traffic. The blob points into the buffer.
    Named(Box<FWP_BYTE_BLOB>, #[allow(dead_code)] Vec<u16>),
    /// A self-relative descriptor that grants `FWP_ACTRL_MATCH_FILTER` to a service SID.
    Service(Box<FWP_BYTE_BLOB>, PSECURITY_DESCRIPTOR),
    /// A UWP package SID.
    Package(PSID),
}

impl AppId {
    fn for_app(app: &AppItem) -> Option<Self> {
        match app.kind {
            AppKind::Regular => Self::file(&app.path),
            AppKind::System => Some(Self::system()),
            AppKind::Service => Self::service(&app.path),
            AppKind::Uwp => Self::package(&app.path),
        }
    }

    fn file(path: &str) -> Option<Self> {
        let path = wide(path);
        let mut blob = std::ptr::null_mut();
        let ok = unsafe { FwpmGetAppIdFromFileName0(PCWSTR(path.as_ptr()), &mut blob) };
        (ok == 0 && !blob.is_null()).then_some(Self::File(blob))
    }

    fn system() -> Self {
        let mut data = wide(SYSTEM_APP);
        let blob = Box::new(FWP_BYTE_BLOB {
            size: (data.len() * 2) as u32,
            data: data.as_mut_ptr() as *mut u8,
        });
        Self::Named(blob, data)
    }

    fn service(name: &str) -> Option<Self> {
        let sid = service_sid(name)?;
        let sddl = wide(&format!("D:(A;;0x{MATCH_FILTER:x};;;{sid})"));
        let mut sd = PSECURITY_DESCRIPTOR::default();
        let mut size = 0u32;
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl.as_ptr()),
                SDDL_REVISION_1,
                &mut sd,
                Some(&mut size),
            )
            .ok()?;
        }
        let blob = Box::new(FWP_BYTE_BLOB { size, data: sd.0 as *mut u8 });
        Some(Self::Service(blob, sd))
    }

    fn package(sid: &str) -> Option<Self> {
        let text = wide(sid);
        let mut psid = PSID::default();
        unsafe { ConvertStringSidToSidW(PCWSTR(text.as_ptr()), &mut psid).ok()? };
        Some(Self::Package(psid))
    }

    fn condition(&self) -> FWPM_FILTER_CONDITION0 {
        match self {
            Self::File(blob) => blob_condition(*blob),
            Self::Named(blob, _) => blob_condition(&**blob as *const _ as *mut _),
            Self::Service(blob, _) => {
                let mut cond = condition(FWPM_CONDITION_ALE_USER_ID, FWP_MATCH_EQUAL, FWP_SECURITY_DESCRIPTOR_TYPE);
                cond.conditionValue.Anonymous.sd = &**blob as *const _ as *mut _;
                cond
            }
            Self::Package(sid) => {
                let mut cond = condition(FWPM_CONDITION_ALE_PACKAGE_ID, FWP_MATCH_EQUAL, FWP_SID);
                cond.conditionValue.Anonymous.sid = sid.0 as *mut SID;
                cond
            }
        }
    }
}

impl Drop for AppId {
    fn drop(&mut self) {
        unsafe {
            match self {
                Self::File(blob) => FwpmFreeMemory0(blob as *mut _ as *mut *mut _),
                Self::Named(..) => {}
                Self::Service(_, sd) => {
                    let _ = LocalFree(Some(HLOCAL(sd.0)));
                }
                Self::Package(sid) => {
                    let _ = LocalFree(Some(HLOCAL(sid.0)));
                }
            }
        }
    }
}

/// `NT SERVICE\<name>` as a SID string. None when the service does not exist.
fn service_sid(name: &str) -> Option<String> {
    let account = wide(&format!(r"NT SERVICE\{name}"));
    let mut sid = vec![0u8; 256];
    let mut sid_len = sid.len() as u32;
    let mut domain = vec![0u16; 256];
    let mut domain_len = domain.len() as u32;
    let mut kind = SID_NAME_USE::default();
    unsafe {
        LookupAccountNameW(
            PCWSTR::null(),
            PCWSTR(account.as_ptr()),
            Some(PSID(sid.as_mut_ptr() as *mut _)),
            &mut sid_len,
            Some(PWSTR(domain.as_mut_ptr())),
            &mut domain_len,
            &mut kind,
        )
        .ok()?;
        let mut text = PWSTR::null();
        ConvertSidToStringSidW(PSID(sid.as_mut_ptr() as *mut _), &mut text).ok()?;
        let out = text.to_string().ok();
        let _ = LocalFree(Some(HLOCAL(text.0 as *mut _)));
        out
    }
}

fn connect_and_accept() -> [windows::core::GUID; 4] {
    [
        FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
        FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
    ]
}

unsafe fn add_filter(
    engine: HANDLE,
    name: &str,
    layer: windows::core::GUID,
    weight: u8,
    permit: bool,
    persistent: bool,
    conds: &mut [FWPM_FILTER_CONDITION0],
) -> Result<(), String> {
    let name_w = wide(name);
    let desc = wide(APP_NAME);
    let mut provider = provider_guid();
    let mut filter = FWPM_FILTER0 {
        displayData: FWPM_DISPLAY_DATA0 {
            name: PWSTR(name_w.as_ptr() as *mut _),
            description: PWSTR(desc.as_ptr() as *mut _),
        },
        flags: if persistent {
            FWPM_FILTER_FLAG_PERSISTENT
        } else {
            FWPM_FILTER_FLAGS(0)
        },
        providerKey: &mut provider,
        layerKey: layer,
        subLayerKey: sublayer_guid(),
        weight: weight_value(weight),
        numFilterConditions: conds.len() as u32,
        filterCondition: if conds.is_empty() {
            std::ptr::null_mut()
        } else {
            conds.as_mut_ptr()
        },
        action: FWPM_ACTION0 {
            r#type: if permit { FWP_ACTION_PERMIT } else { FWP_ACTION_BLOCK },
            ..Default::default()
        },
        ..Default::default()
    };
    let mut id = 0u64;
    win(
        FwpmFilterAdd0(engine, &mut filter, None, Some(&mut id)),
        &format!("filter '{name}'"),
    )
}

fn weight_value(weight: u8) -> FWP_VALUE0 {
    let mut value = FWP_VALUE0 { r#type: FWP_UINT8, ..Default::default() };
    value.Anonymous.uint8 = weight;
    value
}

fn uint32_value(v: u32) -> FWP_VALUE0 {
    let mut value = FWP_VALUE0 { r#type: FWP_UINT32, ..Default::default() };
    value.Anonymous.uint32 = v;
    value
}

fn condition(field: windows::core::GUID, match_type: FWP_MATCH_TYPE, kind: FWP_DATA_TYPE) -> FWPM_FILTER_CONDITION0 {
    let mut cond = FWPM_FILTER_CONDITION0 {
        fieldKey: field,
        matchType: match_type,
        ..Default::default()
    };
    cond.conditionValue.r#type = kind;
    cond
}

fn condition_u8(field: windows::core::GUID, v: u8) -> FWPM_FILTER_CONDITION0 {
    let mut cond = condition(field, FWP_MATCH_EQUAL, FWP_UINT8);
    cond.conditionValue.Anonymous.uint8 = v;
    cond
}

fn condition_u16(field: windows::core::GUID, v: u16) -> FWPM_FILTER_CONDITION0 {
    let mut cond = condition(field, FWP_MATCH_EQUAL, FWP_UINT16);
    cond.conditionValue.Anonymous.uint16 = v;
    cond
}

fn blob_condition(blob: *mut FWP_BYTE_BLOB) -> FWPM_FILTER_CONDITION0 {
    let mut cond = condition(FWPM_CONDITION_ALE_APP_ID, FWP_MATCH_EQUAL, FWP_BYTE_BLOB_TYPE);
    cond.conditionValue.Anonymous.byteBlob = blob;
    cond
}

fn range_u16(low: u16, high: u16) -> FWP_RANGE0 {
    let mut range = FWP_RANGE0::default();
    range.valueLow.r#type = FWP_UINT16;
    range.valueHigh.r#type = FWP_UINT16;
    range.valueLow.Anonymous.uint16 = low;
    range.valueHigh.Anonymous.uint16 = high;
    range
}

/// Host-order IPv4 endpoints, like `_r_byteswap_ulong (S_addr)` in helper.c.
fn range_u32(low: u32, high: u32) -> FWP_RANGE0 {
    let mut range = FWP_RANGE0::default();
    range.valueLow.r#type = FWP_UINT32;
    range.valueHigh.r#type = FWP_UINT32;
    range.valueLow.Anonymous.uint32 = low;
    range.valueHigh.Anonymous.uint32 = high;
    range
}

/// Turn the engine's dropped-packet event buffer on or off (the "UI log" toggle).
pub fn set_packet_log(on: bool) -> Result<(), String> {
    if !is_admin() {
        return Err("Administrator rights are required to change the packets log.".into());
    }
    let engine = Engine::open()?;
    unsafe { set_collect(engine.handle, on) }
}

unsafe fn set_collect(engine: HANDLE, on: bool) -> Result<(), String> {
    win(
        FwpmEngineSetOption0(engine, FWPM_ENGINE_COLLECT_NET_EVENTS, &uint32_value(on as u32)),
        "FwpmEngineSetOption0",
    )
}

/// One dropped connection from the engine's net event buffer.
#[derive(Clone, Debug)]
pub struct Packet {
    pub time: u64,
    pub app: String,
    pub protocol: u8,
    pub local: String,
    pub remote: String,
    pub inbound: bool,
}

/// Drops caused by this provider's filters, newest first.
pub fn dropped_packets(limit: usize) -> Result<Vec<Packet>, String> {
    if !is_admin() {
        return Err("Administrator rights are required to read the packets log.".into());
    }
    let engine = Engine::open()?;
    let mut out = Vec::new();
    let mut ours: HashMap<u64, bool> = HashMap::new();
    let mut inbound: HashMap<u16, bool> = HashMap::new();
    unsafe {
        let mut handle = HANDLE::default();
        win(FwpmNetEventCreateEnumHandle0(engine.handle, None, &mut handle), "net event enum")?;
        loop {
            let mut entries = std::ptr::null_mut();
            let mut returned = 0u32;
            if FwpmNetEventEnum0(engine.handle, handle, 512, &mut entries, &mut returned) != 0
                || returned == 0
                || entries.is_null()
            {
                break;
            }
            for i in 0..returned as usize {
                let event = *entries.add(i);
                if event.is_null() || (*event).r#type != FWPM_NET_EVENT_TYPE_CLASSIFY_DROP {
                    continue;
                }
                let drop = (*event).Anonymous.classifyDrop;
                if drop.is_null() {
                    continue;
                }
                let filter_id = (*drop).filterId;
                let mine = *ours
                    .entry(filter_id)
                    .or_insert_with(|| filter_is_ours(engine.handle, filter_id));
                if !mine {
                    continue;
                }
                let layer = (*drop).layerId;
                let is_inbound = *inbound
                    .entry(layer)
                    .or_insert_with(|| layer_is_inbound(engine.handle, layer));
                out.push(packet(&(*event).header, is_inbound));
            }
            FwpmFreeMemory0(&mut entries as *mut _ as *mut *mut _);
        }
        let _ = FwpmNetEventDestroyEnumHandle0(engine.handle, handle);
    }
    out.sort_by(|a, b| b.time.cmp(&a.time));
    out.truncate(limit);
    Ok(out)
}

unsafe fn filter_is_ours(engine: HANDLE, id: u64) -> bool {
    let mut filter = std::ptr::null_mut();
    if FwpmFilterGetById0(engine, id, &mut filter) != 0 || filter.is_null() {
        return false;
    }
    let provider = (*filter).providerKey;
    let mine = !provider.is_null() && *provider == provider_guid();
    FwpmFreeMemory0(&mut filter as *mut _ as *mut *mut _);
    mine
}

unsafe fn layer_is_inbound(engine: HANDLE, id: u16) -> bool {
    let mut layer = std::ptr::null_mut();
    if FwpmLayerGetById0(engine, id, &mut layer) != 0 || layer.is_null() {
        return false;
    }
    let key = (*layer).layerKey;
    FwpmFreeMemory0(&mut layer as *mut _ as *mut *mut _);
    key == FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4 || key == FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6
}

unsafe fn packet(header: &FWPM_NET_EVENT_HEADER0, inbound: bool) -> Packet {
    let has = |flag: u32| header.flags & flag != 0;
    let v6 = has(FWPM_NET_EVENT_FLAG_IP_VERSION_SET) && header.ipVersion == FWP_IP_VERSION_V6;
    let endpoint = |addr: String, port: u16, port_set: bool| {
        if port_set && port != 0 {
            if v6 { format!("[{addr}]:{port}") } else { format!("{addr}:{port}") }
        } else {
            addr
        }
    };
    let local = if !has(FWPM_NET_EVENT_FLAG_LOCAL_ADDR_SET) {
        String::new()
    } else if v6 {
        Ipv6Addr::from(header.Anonymous1.localAddrV6.byteArray16).to_string()
    } else {
        Ipv4Addr::from(header.Anonymous1.localAddrV4).to_string()
    };
    let remote = if !has(FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET) {
        String::new()
    } else if v6 {
        Ipv6Addr::from(header.Anonymous2.remoteAddrV6.byteArray16).to_string()
    } else {
        Ipv4Addr::from(header.Anonymous2.remoteAddrV4).to_string()
    };
    let app = if has(FWPM_NET_EVENT_FLAG_APP_ID_SET) && !header.appId.data.is_null() {
        let wide = std::slice::from_raw_parts(header.appId.data as *const u16, header.appId.size as usize / 2);
        let path = crate::apps::utf16_prefix(wide);
        path.rsplit('\\').next().unwrap_or(&path).to_string()
    } else {
        SYSTEM_APP.to_string()
    };
    let stamp = (header.timeStamp.dwHighDateTime as u64) << 32 | header.timeStamp.dwLowDateTime as u64;
    Packet {
        time: stamp.saturating_sub(FILETIME_UNIX_EPOCH) / 10_000_000,
        app,
        protocol: if has(FWPM_NET_EVENT_FLAG_IP_PROTOCOL_SET) { header.ipProtocol } else { 0 },
        local: endpoint(local, header.localPort, has(FWPM_NET_EVENT_FLAG_LOCAL_PORT_SET)),
        remote: endpoint(remote, header.remotePort, has(FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET)),
        inbound,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(action: RuleAction, origin: RuleOrigin) -> Rule {
        Rule {
            name: "sample".into(),
            remote: String::new(),
            local: String::new(),
            direction: Direction::Outbound,
            action,
            protocol: 0,
            enabled: true,
            origin,
            apps: Vec::new(),
            services: false,
            kernel: false,
            readonly: false,
        }
    }

    #[test]
    fn user_allow_outranks_blocklist() {
        let allow = sample(RuleAction::Permit, RuleOrigin::User);
        let block = sample(RuleAction::Block, RuleOrigin::Blocklist);
        assert!(rule_weight(&allow, true) > rule_weight(&block, true));
        assert!(rule_weight(&allow, false) < rule_weight(&block, false));
    }

    #[test]
    fn icmp_type_is_the_local_port_field() {
        assert_eq!(ICMP_TYPE, FWPM_CONDITION_IP_LOCAL_PORT);
        assert_ne!(ICMP_TYPE, FWPM_CONDITION_IP_LOCAL_INTERFACE);
    }

    #[test]
    fn rule_without_apps_targets_everyone() {
        let mut rule = sample(RuleAction::Permit, RuleOrigin::System);
        rule.services = true;
        rule.kernel = true;
        assert!(matches!(rule_targets(&rule).as_slice(), [Target::All]));
    }

    #[test]
    fn missing_app_is_not_widened() {
        let mut rule = sample(RuleAction::Permit, RuleOrigin::User);
        rule.apps = vec![r"Z:\does\not\exist.exe".into()];
        assert!(rule_targets(&rule).iter().all(|t| matches!(t, Target::Missing)));
    }

    #[test]
    fn mixed_family_pair_installs_nothing() {
        let rule = sample(RuleAction::Permit, RuleOrigin::User);
        let v4 = rules::parse_rule_list("10.0.0.1").unwrap();
        let v6 = rules::parse_rule_list("[fe80::1]").unwrap();
        // A null engine handle would fail any FwpmFilterAdd0 call, so Ok means no filter was attempted.
        let result = unsafe {
            emit_pair(HANDLE::default(), &rule, WEIGHT_USER, true, false, None, Some(&v4[0]), Some(&v6[0]))
        };
        assert!(result.is_ok());
    }

    #[test]
    fn system_app_id_is_the_literal_name() {
        let id = AppId::system();
        let cond = id.condition();
        let blob = unsafe { &*cond.conditionValue.Anonymous.byteBlob };
        let text = unsafe { std::slice::from_raw_parts(blob.data as *const u16, blob.size as usize / 2) };
        assert_eq!(String::from_utf16_lossy(text), "System\0");
    }
}
