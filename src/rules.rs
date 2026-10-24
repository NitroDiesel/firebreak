//! Rule string parser. Syntax matches the simplewall readme:
//! addresses, `host:port`, ranges, CIDR, ports, and port ranges, split by `;`.

use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Token {
    Port(u16),
    PortRange(u16, u16),
    V4 { addr: u32, mask: u32, port: Option<PortSpec> },
    /// Inclusive host-order endpoints.
    V4Range { start: u32, end: u32, port: Option<PortSpec> },
    V6 { addr: [u8; 16], prefix: u8, port: Option<PortSpec> },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PortSpec {
    One(u16),
    Range(u16, u16),
}

#[derive(Debug, PartialEq, Eq)]
pub struct ParseError(pub String);

pub fn parse_rule_list(input: &str) -> Result<Vec<Token>, ParseError> {
    let mut out = Vec::new();
    if input.trim().is_empty() {
        return Ok(out);
    }
    for part in input.split(';') {
        let part = part.trim().trim_matches(|c| c == '"' || c == '\'');
        if part.is_empty() {
            continue;
        }
        out.push(parse_token(part)?);
    }
    Ok(out)
}

fn parse_token(raw: &str) -> Result<Token, ParseError> {
    if let Some(inner) = raw.strip_prefix('[') {
        return parse_v6(inner);
    }
    if let Some(token) = parse_v4_range_token(raw)? {
        return Ok(token);
    }
    if raw.contains(':') && raw.chars().filter(|c| *c == ':').count() == 1 && !raw.contains('/') {
        let (left, right) = raw.split_once(':').unwrap();
        if looks_like_v4(left) {
            let port = parse_port_spec(right)?;
            let (addr, mask) = parse_v4_cidr(left)?;
            return Ok(Token::V4 {
                addr,
                mask,
                port: Some(port),
            });
        }
    }
    if looks_like_v4(raw) || raw.contains('/') && raw.contains('.') {
        let (addr, mask) = parse_v4_cidr(raw)?;
        return Ok(Token::V4 {
            addr,
            mask,
            port: None,
        });
    }
    if raw.contains('-') && !raw.contains(':') && !raw.contains('.') {
        let (a, b) = split_range(raw)?;
        return Ok(Token::PortRange(parse_port(a)?, parse_port(b)?));
    }
    if raw.chars().all(|c| c.is_ascii_digit()) {
        return Ok(Token::Port(parse_port(raw)?));
    }
    Err(ParseError(format!("unrecognized rule token: {raw}")))
}

fn parse_v6(inner: &str) -> Result<Token, ParseError> {
    let (body, port) = if let Some(idx) = inner.find("]:") {
        let addr = &inner[..idx];
        let port = parse_port_spec(&inner[idx + 2..])?;
        (addr.to_string(), Some(port))
    } else if let Some((addr, rest)) = inner.split_once(']') {
        if rest.is_empty() {
            (addr.to_string(), None)
        } else if let Some(prefix) = rest.strip_prefix('/') {
            (format!("{addr}/{prefix}"), None)
        } else {
            return Err(ParseError(format!("bad ipv6 token: [{inner}")));
        }
    } else {
        return Err(ParseError(format!("bad ipv6 token: [{inner}")));
    };
    let (addr_txt, prefix) = if let Some((a, p)) = body.split_once('/') {
        (a.to_string(), parse_prefix(p, 128)?)
    } else {
        (body, 128)
    };
    let ip: Ipv6Addr = addr_txt
        .parse()
        .map_err(|_| ParseError(format!("bad ipv6 address: {addr_txt}")))?;
    Ok(Token::V6 {
        addr: ip.octets(),
        prefix,
        port,
    })
}

fn looks_like_v4(s: &str) -> bool {
    let head = s.split('/').next().unwrap_or(s);
    let head = head.split('-').next().unwrap_or(head);
    head.split('.').count() == 4 && head.chars().all(|c| c.is_ascii_digit() || c == '.')
}

fn parse_v4_range_token(raw: &str) -> Result<Option<Token>, ParseError> {
    let (left, rest) = match raw.split_once('-') {
        Some(pair) => pair,
        None => return Ok(None),
    };
    if !looks_like_v4(left) {
        return Ok(None);
    }
    let (end_txt, port) = if let Some((addr, port)) = rest.rsplit_once(':') {
        if port.contains('.') {
            (rest, None)
        } else {
            (addr, Some(parse_port_spec(port)?))
        }
    } else {
        (rest, None)
    };
    if !looks_like_v4(end_txt) {
        return Ok(None);
    }
    let start = u32::from(parse_v4(left)?);
    let end = u32::from(parse_v4(end_txt)?);
    if start > end {
        return Err(ParseError(format!("inverted range: {raw}")));
    }
    Ok(Some(Token::V4Range { start, end, port }))
}

fn parse_v4_cidr(raw: &str) -> Result<(u32, u32), ParseError> {
    if let Some((addr, prefix)) = raw.split_once('/') {
        let ip = parse_v4(addr)?;
        let prefix: u8 = prefix
            .parse()
            .map_err(|_| ParseError(format!("bad prefix: {prefix}")))?;
        if prefix > 32 {
            return Err(ParseError(format!("ipv4 prefix {prefix}")));
        }
        let mask = prefix_mask(prefix);
        return Ok((u32::from(ip) & mask, mask));
    }
    let ip = parse_v4(raw)?;
    Ok((u32::from(ip), prefix_mask(32)))
}

fn parse_v4(raw: &str) -> Result<Ipv4Addr, ParseError> {
    raw.parse()
        .map_err(|_| ParseError(format!("bad ipv4 address: {raw}")))
}

fn parse_port_spec(raw: &str) -> Result<PortSpec, ParseError> {
    if let Some((a, b)) = raw.split_once('-') {
        Ok(PortSpec::Range(parse_port(a)?, parse_port(b)?))
    } else {
        Ok(PortSpec::One(parse_port(raw)?))
    }
}

fn parse_port(raw: &str) -> Result<u16, ParseError> {
    let n: u32 = raw
        .trim()
        .parse()
        .map_err(|_| ParseError(format!("bad port: {raw}")))?;
    if n == 0 || n > 65535 {
        return Err(ParseError(format!("port out of range: {raw}")));
    }
    Ok(n as u16)
}

fn split_range(raw: &str) -> Result<(&str, &str), ParseError> {
    raw.split_once('-')
        .ok_or_else(|| ParseError(format!("bad range: {raw}")))
}

fn parse_prefix(raw: &str, max: u8) -> Result<u8, ParseError> {
    let n: u16 = raw
        .trim()
        .trim_end_matches(']')
        .parse()
        .map_err(|_| ParseError(format!("bad prefix: {raw}")))?;
    if n > max as u16 {
        return Err(ParseError(format!("prefix {n} exceeds {max}")));
    }
    Ok(n as u8)
}

/// Host-order mask, so `/16` is `0xFFFF_0000`. WFP takes IPv4 values in host order.
pub fn prefix_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        !0u32 << (32 - prefix)
    }
}

pub fn v6_mask(prefix: u8) -> [u8; 16] {
    let mut mask = [0u8; 16];
    let mut left = prefix;
    for byte in &mut mask {
        if left == 0 {
            break;
        }
        if left >= 8 {
            *byte = 0xff;
            left -= 8;
        } else {
            *byte = 0xff << (8 - left);
            left = 0;
        }
    }
    mask
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ports_and_ranges() {
        let t = parse_rule_list("80; 443; 20-21").unwrap();
        assert_eq!(
            t,
            vec![
                Token::Port(80),
                Token::Port(443),
                Token::PortRange(20, 21)
            ]
        );
    }

    #[test]
    fn cidr_and_host_port() {
        let t = parse_rule_list("192.168.0.0/16; 192.168.0.1:443").unwrap();
        assert!(matches!(t[0], Token::V4 { mask, .. } if mask == prefix_mask(16)));
        assert!(matches!(
            t[1],
            Token::V4 {
                port: Some(PortSpec::One(443)),
                ..
            }
        ));
    }

    #[test]
    fn ipv4_is_host_order() {
        let t = parse_rule_list("192.168.1.7/16; 10.0.0.1-10.0.0.9").unwrap();
        assert_eq!(
            t[0],
            Token::V4 {
                addr: 0xC0A8_0000,
                mask: 0xFFFF_0000,
                port: None
            }
        );
        assert_eq!(
            t[1],
            Token::V4Range {
                start: 0x0A00_0001,
                end: 0x0A00_0009,
                port: None
            }
        );
    }

    #[test]
    fn internal_rule_text_parses() {
        let xml = include_str!("../resources/profile_internal.xml");
        let mut bad = Vec::new();
        for attr in [" rule=\"", " rule_local=\""] {
            for part in xml.split(attr).skip(1) {
                let text = part.split('"').next().unwrap_or_default();
                if parse_rule_list(text).is_err() {
                    bad.push(text.to_string());
                }
            }
        }
        assert!(bad.is_empty(), "unparsed: {bad:?}");
    }

    #[test]
    fn ipv6_bracket() {
        let t = parse_rule_list("[fc00::]/7; [fe80::]:5355").unwrap();
        assert!(matches!(t[0], Token::V6 { prefix: 7, .. }));
        assert!(matches!(
            t[1],
            Token::V6 {
                port: Some(PortSpec::One(5355)),
                ..
            }
        ));
    }
}
