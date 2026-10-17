//! Windows Filtering Platform engine.
//!
//! Provider `B0D553E2-...` and sublayer `9FEE6F59-...` match `src/wfp.h`, so
//! Disable filters removes filters this port (and the original simplewall)
//! installed under that provider.
//!
//! Install is explicit. Nothing here runs during `cargo test`.

use std::net::Ipv4Addr;

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::*;
use windows::Win32::UI::Shell::IsUserAnAdmin;

use crate::apps::resolve_service_image;
use crate::model::{AppItem, Direction, Profile, Rule, RuleAction, RuleOrigin, APP_NAME};
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
const LOOPBACK: u32 = 0x0000_0001;
/// `FWPM_CONDITION_ICMP_TYPE` from fwpmu.h. The windows crate omits this GUID.
const ICMP_TYPE: windows::core::GUID =
    windows::core::GUID::from_u128(0x4cd62a49_59c3_4969_b7f3_bda5d32890a4);

fn win(code: u32, what: &str) -> Result<(), String> {
    if code == 0 {
        Ok(())
    } else {
        Err(format!("{what} failed ({code})"))
    }
}

pub fn is_admin() -> bool {
    unsafe { IsUserAnAdmin().as_bool() }
}

pub fn filters_installed() -> Result<bool, String> {
    let engine = Engine::open(false)?;
    Ok(unsafe { provider_present(engine.handle) })
}

pub fn install(profile: &Profile, temporary: bool) -> Result<String, String> {
    if !is_admin() {
        return Err("administrator rights are required to change filters".into());
    }
    let engine = Engine::open(temporary)?;
    unsafe {
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
            add_rules(engine.handle, profile, !temporary)?;
            add_apps(engine.handle, profile, !temporary)?;
            add_self(engine.handle, !temporary)?;
            add_block_all(engine.handle, !temporary)?;
            Ok(())
        })();
        if let Err(err) = result {
            let _ = FwpmTransactionAbort0(engine.handle);
            return Err(err);
        }
        transact(engine.handle, false)?;
    }
    let mode = if temporary { "temporary (until reboot)" } else { "permanent" };
    Ok(format!("filters installed ({mode})"))
}

pub fn uninstall() -> Result<String, String> {
    if !is_admin() {
        return Err("administrator rights are required to change filters".into());
    }
    let engine = Engine::open(false)?;
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
            return Err("filters were not fully removed; run -uninstall again as administrator".into());
        }
    }
    Ok("filters removed".into())
}

struct Engine {
    handle: HANDLE,
}

impl Engine {
    fn open(temporary: bool) -> Result<Self, String> {
        unsafe {
            let name = wide(APP_NAME);
            let desc = wide("simplewall rust session");
            let session = FWPM_SESSION0 {
                displayData: FWPM_DISPLAY_DATA0 {
                    name: PWSTR(name.as_ptr() as *mut _),
                    description: PWSTR(desc.as_ptr() as *mut _),
                },
                flags: if temporary { FWPM_SESSION_FLAG_DYNAMIC } else { 0 },
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

unsafe fn add_loopback(engine: HANDLE, persistent: bool) -> Result<(), String> {
    let cond = condition_flags(LOOPBACK);
    for layer in connect_and_accept() {
        add_filter(
            engine,
            "AllowLoopback",
            layer,
            WEIGHT_IMPORTANT,
            true,
            persistent,
            &mut [cond],
        )?;
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
    for icmp in [0x85u16, 0x86, 0x87, 0x88] {
        let mut cond = condition_u16(ICMP_TYPE, icmp);
        add_filter(
            engine,
            "AllowIcmpV6",
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
    let app = AppItem {
        path: path.to_string_lossy().into_owned(),
        display_name: "simplewall".into(),
        kind: crate::model::AppKind::Regular,
        enabled: true,
        timer_until: 0,
        comment: String::new(),
        pinned: false,
    };
    add_app_permit(engine, &app, persistent)
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
    add_one_rule(engine, &rule, persistent, WEIGHT_IMPORTANT)
}

unsafe fn add_apps(engine: HANDLE, profile: &Profile, persistent: bool) -> Result<(), String> {
    for app in &profile.apps {
        if !app.allowed_now() {
            continue;
        }
        add_app_permit(engine, app, persistent)?;
    }
    Ok(())
}

unsafe fn add_app_permit(engine: HANDLE, app: &AppItem, persistent: bool) -> Result<(), String> {
    let path = wide(&app.path);
    let mut blob = std::ptr::null_mut();
    if FwpmGetAppIdFromFileName0(PCWSTR(path.as_ptr()), &mut blob) != 0 || blob.is_null() {
        return Ok(());
    }
    let mut cond = condition_blob(FWPM_CONDITION_ALE_APP_ID, blob);
    for layer in connect_and_accept() {
        let _ = add_filter(
            engine,
            &app.display_name,
            layer,
            WEIGHT_APP,
            true,
            persistent,
            std::slice::from_mut(&mut cond),
        );
    }
    FwpmFreeMemory0(&mut blob as *mut _ as *mut *mut _);
    Ok(())
}

unsafe fn add_rules(engine: HANDLE, profile: &Profile, persistent: bool) -> Result<(), String> {
    for rule in &profile.rules {
        if !rule.enabled {
            continue;
        }
        add_one_rule(engine, rule, persistent, rule_weight(rule, profile.settings.user_allows_override_blocklist))?;
    }
    Ok(())
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

unsafe fn add_one_rule(
    engine: HANDLE,
    rule: &Rule,
    persistent: bool,
    weight: u8,
) -> Result<(), String> {
    let paths = rule_paths(rule);
    let remote = rules::parse_rule_list(&rule.remote).unwrap_or_default();
    let local = rules::parse_rule_list(&rule.local).unwrap_or_default();
    let permit = rule.action == RuleAction::Permit;
    let targets: Vec<Option<&str>> = if paths.is_empty() {
        vec![None]
    } else {
        paths.iter().map(|p| Some(p.as_str())).collect()
    };
    let mut blobs: Vec<*mut FWP_BYTE_BLOB> = Vec::new();
    for app in targets {
        let blob = if let Some(path) = app {
            let wide_path = wide(path);
            let mut blob = std::ptr::null_mut();
            if FwpmGetAppIdFromFileName0(PCWSTR(wide_path.as_ptr()), &mut blob) != 0 || blob.is_null() {
                continue;
            }
            blobs.push(blob);
            Some(blob)
        } else {
            None
        };
        emit_rule_filters(engine, rule, weight, permit, persistent, blob, &remote, &local)?;
    }
    for blob in blobs {
        let mut p = blob;
        FwpmFreeMemory0(&mut p as *mut _ as *mut *mut _);
    }
    Ok(())
}

unsafe fn emit_rule_filters(
    engine: HANDLE,
    rule: &Rule,
    weight: u8,
    permit: bool,
    persistent: bool,
    blob: Option<*mut FWP_BYTE_BLOB>,
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
            if made > 128 {
                return Ok(());
            }
            emit_pair(engine, rule, weight, permit, persistent, blob, *remote, *local)?;
            made += 1;
        }
    }
    Ok(())
}

unsafe fn emit_pair(
    engine: HANDLE,
    rule: &Rule,
    weight: u8,
    permit: bool,
    persistent: bool,
    blob: Option<*mut FWP_BYTE_BLOB>,
    remote: Option<&Token>,
    local: Option<&Token>,
) -> Result<(), String> {
    let v6 = matches!(remote, Some(Token::V6 { .. })) || matches!(local, Some(Token::V6 { .. }));
    let v4 = matches!(remote, Some(Token::V4 { .. } | Token::V4Range { .. }))
        || matches!(local, Some(Token::V4 { .. } | Token::V4Range { .. }));
    let families: &[bool] = if v6 && !v4 {
        &[true]
    } else if v4 && !v6 {
        &[false]
    } else {
        &[false, true]
    };
    for ipv6 in families {
        let layers: Vec<windows::core::GUID> = match rule.direction {
            Direction::Inbound => vec![if *ipv6 {
                FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6
            } else {
                FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4
            }],
            Direction::Outbound => vec![if *ipv6 {
                FWPM_LAYER_ALE_AUTH_CONNECT_V6
            } else {
                FWPM_LAYER_ALE_AUTH_CONNECT_V4
            }],
            Direction::Any => vec![
                if *ipv6 {
                    FWPM_LAYER_ALE_AUTH_CONNECT_V6
                } else {
                    FWPM_LAYER_ALE_AUTH_CONNECT_V4
                },
                if *ipv6 {
                    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6
                } else {
                    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4
                },
            ],
        };
        for layer in layers {
            let mut storage = CondStore::default();
            let conds = storage.fill(rule.protocol, blob, remote, local, *ipv6, layer_is_recv(&layer));
            if conds.is_empty() && blob.is_none() && rule.protocol == 0 {
                continue;
            }
            add_filter(engine, &rule.name, layer, weight, permit, persistent, conds)?;
        }
    }
    Ok(())
}

fn layer_is_recv(layer: &windows::core::GUID) -> bool {
    layer == &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4 || layer == &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6
}

struct CondStore {
    conds: Vec<FWPM_FILTER_CONDITION0>,
    v4: Vec<FWP_V4_ADDR_AND_MASK>,
    v6: Vec<FWP_V6_ADDR_AND_MASK>,
    ranges: Vec<FWP_RANGE0>,
}

impl Default for CondStore {
    fn default() -> Self {
        Self {
            conds: Vec::new(),
            v4: Vec::new(),
            v6: Vec::new(),
            ranges: Vec::new(),
        }
    }
}

impl CondStore {
    fn fill(
        &mut self,
        protocol: u8,
        blob: Option<*mut FWP_BYTE_BLOB>,
        remote: Option<&Token>,
        local: Option<&Token>,
        ipv6: bool,
        recv: bool,
    ) -> &mut [FWPM_FILTER_CONDITION0] {
        if protocol != 0 {
            self.conds.push(condition_u8(FWPM_CONDITION_IP_PROTOCOL, protocol));
        }
        if let Some(blob) = blob {
            self.conds.push(condition_blob(FWPM_CONDITION_ALE_APP_ID, blob));
        }
        if let Some(token) = remote {
            let field = if recv {
                FWPM_CONDITION_IP_LOCAL_ADDRESS
            } else {
                FWPM_CONDITION_IP_REMOTE_ADDRESS
            };
            let port_field = if recv {
                FWPM_CONDITION_IP_LOCAL_PORT
            } else {
                FWPM_CONDITION_IP_REMOTE_PORT
            };
            // On the outbound connect layer the "remote" text is the peer.
            // `recv` here is the layer, not the rule direction. For an inbound
            // rule the remote text is still the peer, which is the remote
            // address on RECV_ACCEPT. Override the swap above.
            let _ = (field, port_field);
            self.push_token(token, false, ipv6);
        }
        if let Some(token) = local {
            self.push_token(token, true, ipv6);
        }
        &mut self.conds
    }

    fn push_token(&mut self, token: &Token, local: bool, ipv6: bool) {
        let addr_key = if local {
            FWPM_CONDITION_IP_LOCAL_ADDRESS
        } else {
            FWPM_CONDITION_IP_REMOTE_ADDRESS
        };
        let port_key = if local {
            FWPM_CONDITION_IP_LOCAL_PORT
        } else {
            FWPM_CONDITION_IP_REMOTE_PORT
        };
        match token {
            Token::Port(p) => self.conds.push(condition_u16(port_key, *p)),
            Token::PortRange(a, b) => self.push_port_range(port_key, *a, *b),
            Token::V4 { addr, mask, port } if !ipv6 => {
                self.v4.push(FWP_V4_ADDR_AND_MASK { addr: *addr, mask: *mask });
                let ptr = self.v4.last_mut().unwrap() as *mut _;
                self.conds.push(condition_v4(addr_key, ptr));
                self.push_port(port_key, port.as_ref());
            }
            Token::V4Range { start, end, port } if !ipv6 => {
                self.push_addr_range(addr_key, start.to_be(), end.to_be());
                self.push_port(port_key, port.as_ref());
            }
            Token::V6 { addr, prefix, port } if ipv6 => {
                let mut masked = *addr;
                let mask = rules::v6_mask(*prefix);
                for (b, m) in masked.iter_mut().zip(mask) {
                    *b &= m;
                }
                self.v6.push(FWP_V6_ADDR_AND_MASK {
                    addr: masked,
                    prefixLength: *prefix,
                });
                let ptr = self.v6.last_mut().unwrap() as *mut _;
                self.conds.push(condition_v6(addr_key, ptr));
                self.push_port(port_key, port.as_ref());
            }
            _ => {}
        }
    }

    fn push_port(&mut self, key: windows::core::GUID, port: Option<&PortSpec>) {
        match port {
            Some(PortSpec::One(p)) => self.conds.push(condition_u16(key, *p)),
            Some(PortSpec::Range(a, b)) => self.push_port_range(key, *a, *b),
            None => {}
        }
    }

    fn push_port_range(&mut self, key: windows::core::GUID, low: u16, high: u16) {
        self.ranges.push(range_u16(low, high));
        let ptr = self.ranges.last_mut().unwrap() as *mut _;
        self.conds.push(condition_range(key, ptr));
    }

    fn push_addr_range(&mut self, key: windows::core::GUID, low: u32, high: u32) {
        self.ranges.push(range_u32(low, high));
        let ptr = self.ranges.last_mut().unwrap() as *mut _;
        self.conds.push(condition_range(key, ptr));
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

fn rule_paths(rule: &Rule) -> Vec<String> {
    let mut paths = Vec::new();
    for app in &rule.apps {
        let expanded = expand_path(app);
        if expanded.contains('\\') || expanded.contains(':') {
            paths.push(expanded);
        } else if let Some(image) = resolve_service_image(&expanded) {
            paths.push(image);
        }
    }
    if rule.kernel {
        if let Ok(root) = std::env::var("SYSTEMROOT") {
            paths.push(format!("{root}\\System32\\ntoskrnl.exe"));
        }
    }
    paths.sort();
    paths.dedup();
    paths
}

fn expand_path(path: &str) -> String {
    let root = std::env::var("SYSTEMROOT").unwrap_or_else(|_| r"C:\Windows".into());
    path.replace("%systemroot%", &root)
        .replace("%SystemRoot%", &root)
        .replace("%SYSTEMROOT%", &root)
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
    let mut value = FWP_VALUE0::default();
    value.r#type = FWP_UINT8;
    value.Anonymous.uint8 = weight;
    value
}

fn condition_u8(field: windows::core::GUID, v: u8) -> FWPM_FILTER_CONDITION0 {
    let mut cond = FWPM_FILTER_CONDITION0 {
        fieldKey: field,
        matchType: FWP_MATCH_EQUAL,
        ..Default::default()
    };
    cond.conditionValue.r#type = FWP_UINT8;
    cond.conditionValue.Anonymous.uint8 = v;
    cond
}

fn condition_u16(field: windows::core::GUID, v: u16) -> FWPM_FILTER_CONDITION0 {
    let mut cond = FWPM_FILTER_CONDITION0 {
        fieldKey: field,
        matchType: FWP_MATCH_EQUAL,
        ..Default::default()
    };
    cond.conditionValue.r#type = FWP_UINT16;
    cond.conditionValue.Anonymous.uint16 = v;
    cond
}

fn condition_flags(flags: u32) -> FWPM_FILTER_CONDITION0 {
    let mut cond = FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_FLAGS,
        matchType: FWP_MATCH_FLAGS_ALL_SET,
        ..Default::default()
    };
    cond.conditionValue.r#type = FWP_UINT32;
    cond.conditionValue.Anonymous.uint32 = flags;
    cond
}

fn condition_blob(field: windows::core::GUID, blob: *mut FWP_BYTE_BLOB) -> FWPM_FILTER_CONDITION0 {
    let mut cond = FWPM_FILTER_CONDITION0 {
        fieldKey: field,
        matchType: FWP_MATCH_EQUAL,
        ..Default::default()
    };
    cond.conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
    cond.conditionValue.Anonymous.byteBlob = blob;
    cond
}

fn condition_v4(field: windows::core::GUID, mask: *mut FWP_V4_ADDR_AND_MASK) -> FWPM_FILTER_CONDITION0 {
    let mut cond = FWPM_FILTER_CONDITION0 {
        fieldKey: field,
        matchType: FWP_MATCH_EQUAL,
        ..Default::default()
    };
    cond.conditionValue.r#type = FWP_V4_ADDR_MASK;
    cond.conditionValue.Anonymous.v4AddrMask = mask;
    cond
}

fn condition_v6(field: windows::core::GUID, mask: *mut FWP_V6_ADDR_AND_MASK) -> FWPM_FILTER_CONDITION0 {
    let mut cond = FWPM_FILTER_CONDITION0 {
        fieldKey: field,
        matchType: FWP_MATCH_EQUAL,
        ..Default::default()
    };
    cond.conditionValue.r#type = FWP_V6_ADDR_MASK;
    cond.conditionValue.Anonymous.v6AddrMask = mask;
    cond
}

fn condition_range(field: windows::core::GUID, range: *mut FWP_RANGE0) -> FWPM_FILTER_CONDITION0 {
    let mut cond = FWPM_FILTER_CONDITION0 {
        fieldKey: field,
        matchType: FWP_MATCH_RANGE,
        ..Default::default()
    };
    cond.conditionValue.r#type = FWP_RANGE_TYPE;
    cond.conditionValue.Anonymous.rangeValue = range;
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

fn range_u32(low: u32, high: u32) -> FWP_RANGE0 {
    let mut range = FWP_RANGE0::default();
    range.valueLow.r#type = FWP_UINT32;
    range.valueHigh.r#type = FWP_UINT32;
    range.valueLow.Anonymous.uint32 = low;
    range.valueHigh.Anonymous.uint32 = high;
    range
}

fn wide(s: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

#[allow(dead_code)]
fn _keep_ipv4(addr: Ipv4Addr) -> u32 {
    u32::from(addr).to_be()
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
}
