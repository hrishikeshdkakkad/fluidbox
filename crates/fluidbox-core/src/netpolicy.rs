//! Pure SSRF address policy: the `ip_blocked` predicate and a hand-rolled
//! `IpCidr` allowlist parser, with NO I/O.
//!
//! This lives in `fluidbox-core` (not `fluidbox-server`) on purpose: TWO
//! consumers need the identical predicate and the crate dependency direction
//! forbids `fluidbox-workspace` importing `fluidbox-server`. `fluidbox-server`'s
//! `egress` module re-exports these for its hardened reqwest clients and
//! pre-dial `admit_url`; `fluidbox-workspace` uses them to validate git clone
//! hosts. Keeping the range logic in ONE unit-tested place means the broker,
//! delivery, OIDC, connector-OAuth, and git-clone paths cannot drift apart.
//!
//! Stable-only checks: the IPv6 ULA/link-local/multicast/site-local/doc ranges
//! and the IPv4 reserved ranges are computed by hand because the corresponding
//! `std` helpers are still nightly.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// A single CIDR block in the egress allowlist (`FLUIDBOX_EGRESS_ALLOW_CIDRS`).
/// Hand-rolled (no external `ipnet`/`cidr` dependency) — Phase E adds exactly
/// one sanctioned crate (`jsonschema`) and this is not it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpCidr {
    pub addr: IpAddr,
    pub prefix: u8,
}

impl IpCidr {
    /// True iff `ip` falls inside this block. Cross-family (v4 block vs v6 ip)
    /// never matches EXCEPT a v4-mapped v6 address, which is compared on its v4
    /// form so an operator writing `10.0.0.0/8` also covers `::ffff:10.0.0.1`.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => cidr_match_v4(net, ip, self.prefix),
            (IpAddr::V6(net), IpAddr::V6(ip)) => cidr_match_v6(net, ip, self.prefix),
            (IpAddr::V4(_), IpAddr::V6(ip)) => ip
                .to_ipv4_mapped()
                .map(|m| self.contains(IpAddr::V4(m)))
                .unwrap_or(false),
            (IpAddr::V6(_), IpAddr::V4(_)) => false,
        }
    }
}

impl FromStr for IpCidr {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        let s = s.trim();
        let (addr_str, prefix_str) = s
            .split_once('/')
            .ok_or_else(|| format!("CIDR '{s}' must be addr/prefix"))?;
        let addr: IpAddr = addr_str
            .trim()
            .parse()
            .map_err(|_| format!("CIDR '{s}' has an invalid address"))?;
        let prefix: u8 = prefix_str
            .trim()
            .parse()
            .map_err(|_| format!("CIDR '{s}' has an invalid prefix"))?;
        let max = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix > max {
            return Err(format!("CIDR '{s}' prefix exceeds /{max}"));
        }
        Ok(IpCidr { addr, prefix })
    }
}

fn cidr_match_v4(net: Ipv4Addr, ip: Ipv4Addr, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    let mask: u32 = u32::MAX << (32 - prefix as u32);
    (u32::from(net) & mask) == (u32::from(ip) & mask)
}

fn cidr_match_v6(net: Ipv6Addr, ip: Ipv6Addr, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    let mask: u128 = u128::MAX << (128 - prefix as u32);
    (u128::from(net) & mask) == (u128::from(ip) & mask)
}

/// Reject private/loopback/link-local/metadata/CGNAT/reserved/multicast ranges.
///
/// `dev` (the loopback-dev seam, keyed off a loopback-http `FLUIDBOX_PUBLIC_URL`)
/// permits ONLY loopback — never link-local, so the cloud-metadata endpoint
/// `169.254.169.254` (inside 169.254.0.0/16) stays blocked in dev too. `allow`
/// is the operator escape hatch: an explicitly allowlisted address is never
/// blocked (a private LiteLLM / GHES / metadata endpoint the deployment opts
/// into); it overrides every range below.
pub fn ip_blocked(ip: IpAddr, dev: bool, allow: &[IpCidr]) -> bool {
    // Normalize a v4-mapped v6 address to its v4 form up front so both the
    // allowlist and the range checks see one canonical address.
    if let IpAddr::V6(a) = ip {
        if let Some(v4) = a.to_ipv4_mapped() {
            return ip_blocked(IpAddr::V4(v4), dev, allow);
        }
    }
    if allow.iter().any(|c| c.contains(ip)) {
        return false;
    }
    let blocked = match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            a.is_loopback()
                || a.is_private()
                || a.is_link_local() // 169.254/16 incl. the metadata endpoint
                || a.is_broadcast()
                || a.is_documentation()
                || a.is_unspecified()
                || (o[0] == 100 && (o[1] & 0xc0) == 64) // 100.64/10 CGNAT
                || o[0] == 0 // 0.0.0.0/8 "this network"
                || (o[0] & 0xf0) == 224 // 224/4 multicast
                || (o[0] & 0xf0) == 240 // 240/4 reserved (incl. 255/8)
                || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0.0/24 IETF proto assignments
                || (o[0] == 198 && (o[1] & 0xfe) == 18) // 198.18/15 benchmarking
        }
        IpAddr::V6(a) => {
            let s = a.segments();
            let s0 = s[0];
            a.is_loopback()
                || a.is_unspecified()
                || (s0 & 0xfe00) == 0xfc00 // fc00::/7 unique-local
                || (s0 & 0xffc0) == 0xfe80 // fe80::/10 link-local
                || (s0 & 0xff00) == 0xff00 // ff00::/8 multicast
                || (s0 & 0xffc0) == 0xfec0 // fec0::/10 site-local (deprecated)
                || (s0 == 0x2001 && s[1] == 0x0db8) // 2001:db8::/32 documentation
        }
    };
    blocked && !(dev && ip.is_loopback())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn blocks_classic_private_and_loopback_ranges() {
        let b = |s: &str| ip_blocked(ip(s), false, &[]);
        assert!(b("127.0.0.1"));
        assert!(b("10.0.0.5"));
        assert!(b("192.168.1.1"));
        assert!(b("172.16.0.1"));
        assert!(b("100.64.1.1")); // CGNAT
        assert!(b("::1"));
        assert!(b("fe80::1")); // link-local
        assert!(b("fc00::1")); // unique-local
                               // A routable public address is allowed.
        assert!(!b("93.184.216.34"));
        assert!(!b("2606:2800:220:1::1"));
    }

    #[test]
    fn blocks_metadata_even_in_dev() {
        // dev un-blocks loopback ONLY; the cloud-metadata endpoint is link-local
        // (169.254/16), not loopback — the acceptance-script SSRF split depends
        // on this. Both v4 and its v4-mapped v6 form stay blocked.
        assert!(ip_blocked(ip("169.254.169.254"), true, &[]));
        assert!(ip_blocked(ip("169.254.169.254"), false, &[]));
        assert!(ip_blocked(ip("::ffff:169.254.169.254"), true, &[]));
        // …while loopback flips with the dev seam.
        assert!(ip_blocked(ip("127.0.0.1"), false, &[]));
        assert!(!ip_blocked(ip("127.0.0.1"), true, &[]));
        assert!(!ip_blocked(ip("::1"), true, &[]));
    }

    #[test]
    fn blocks_extended_reserved_ranges() {
        let b = |s: &str| ip_blocked(ip(s), false, &[]);
        assert!(b("0.0.0.0")); // 0.0.0.0/8
        assert!(b("0.1.2.3"));
        assert!(b("224.0.0.1")); // multicast
        assert!(b("239.255.255.250"));
        assert!(b("240.0.0.1")); // reserved
        assert!(b("255.255.255.255")); // broadcast / 240-4
        assert!(b("192.0.0.1")); // 192.0.0.0/24
        assert!(b("198.18.0.1")); // benchmarking 198.18/15
        assert!(b("198.19.255.255"));
        assert!(b("ff02::1")); // v6 multicast
        assert!(b("fec0::1")); // v6 site-local
        assert!(b("2001:db8::1")); // v6 documentation
                                   // A neighbour just outside 198.18/15 is public.
        assert!(!b("198.20.0.1"));
    }

    #[test]
    fn v4_mapped_v6_recurses_to_v4_decision() {
        // ::ffff:10.0.0.1 must be blocked like 10.0.0.1; ::ffff:93.184.216.34 allowed.
        assert!(ip_blocked(ip("::ffff:10.0.0.1"), false, &[]));
        assert!(!ip_blocked(ip("::ffff:93.184.216.34"), false, &[]));
    }

    #[test]
    fn allow_cidr_overrides_the_block_and_is_scoped() {
        let allow: Vec<IpCidr> = vec!["10.0.0.0/8".parse().unwrap()];
        // FALSE-GREEN guard: the SAME address is blocked without the allowlist…
        assert!(ip_blocked(ip("10.1.2.3"), false, &[]));
        // …and admitted with it (the escape hatch).
        assert!(!ip_blocked(ip("10.1.2.3"), false, &allow));
        // A v4-mapped form of the same address is covered too.
        assert!(!ip_blocked(ip("::ffff:10.1.2.3"), false, &allow));
        // The allowlist is scoped: a DIFFERENT private address is still blocked.
        assert!(ip_blocked(ip("192.168.0.1"), false, &allow));
        // A /32 host entry admits exactly one address.
        let one: Vec<IpCidr> = vec!["169.254.169.254/32".parse().unwrap()];
        assert!(!ip_blocked(ip("169.254.169.254"), false, &one));
        assert!(ip_blocked(ip("169.254.169.253"), false, &one));
    }

    #[test]
    fn ipcidr_parses_and_rejects() {
        let c: IpCidr = "10.0.0.0/8".parse().unwrap();
        assert_eq!(c.prefix, 8);
        assert!(c.contains(ip("10.255.255.255")));
        assert!(!c.contains(ip("11.0.0.0")));
        // /0 matches everything of its family.
        let all4: IpCidr = "0.0.0.0/0".parse().unwrap();
        assert!(all4.contains(ip("8.8.8.8")));
        assert!(!all4.contains(ip("::1")));
        // v6 block.
        let c6: IpCidr = "fd00::/8".parse().unwrap();
        assert!(c6.contains(ip("fd12::34")));
        assert!(!c6.contains(ip("fe80::1")));
        // Malformed / out-of-range → error, never a silent wildcard.
        assert!("10.0.0.0".parse::<IpCidr>().is_err());
        assert!("10.0.0.0/33".parse::<IpCidr>().is_err());
        assert!("::1/129".parse::<IpCidr>().is_err());
        assert!("not-an-ip/8".parse::<IpCidr>().is_err());
        assert!("10.0.0.0/x".parse::<IpCidr>().is_err());
    }
}
