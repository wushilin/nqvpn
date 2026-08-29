//! What this host already routes locally, so member prefixes that would
//! capture it are never installed (DESIGN.md §8).

use ipnet::IpNet;
use std::net::IpAddr;

/// Prefixes configured on this host's interfaces, excluding loopback and
/// the named device (our own TUN). Each address with a netmask yields its
/// connected prefix; one without yields a host route.
pub fn local_prefixes(exclude_device: &str) -> Vec<IpNet> {
    let mut out = Vec::new();
    let Ok(ifaces) = getifaddrs::getifaddrs() else { return out };
    for i in ifaces {
        if i.name == exclude_device || i.flags.contains(getifaddrs::InterfaceFlags::LOOPBACK) {
            continue;
        }
        let Some(addr) = i.address.ip_addr() else { continue };
        if addr.is_loopback() || addr.is_unspecified() {
            continue;
        }
        let plen = match (addr, i.address.netmask()) {
            (IpAddr::V4(_), Some(IpAddr::V4(m))) => u32::from(m).count_ones() as u8,
            (IpAddr::V6(_), Some(IpAddr::V6(m))) => u128::from(m).count_ones() as u8,
            (IpAddr::V4(_), _) => 32,
            (IpAddr::V6(_), _) => 128,
        };
        if let Ok(net) = IpNet::new(addr, plen) {
            // Link-local v6 is on every interface and never routed.
            if let IpNet::V6(v6) = net {
                if (v6.addr().segments()[0] & 0xffc0) == 0xfe80 {
                    continue;
                }
            }
            out.push(net.trunc());
        }
    }
    out.sort_by_key(|n| n.to_string());
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enumerates_without_loopback() {
        let v = local_prefixes("no-such-device");
        assert!(v.iter().all(|n| !n.addr().is_loopback()));
    }
}
