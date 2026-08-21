//! Socket-scoped direct routing for a compiled-in self-hosted server.
//!
//! On Windows, full-tunnel VPN clients normally win route selection by
//! installing a default route through their TUN adapter.  `IP_UNICAST_IF`
//! lets this client select a physical interface for an individual socket
//! without changing the machine-wide routing table.

use crate::config::{keys, Config};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[derive(Clone, Debug)]
pub struct DirectInterface {
    pub index: u32,
    pub local_ip: Ipv4Addr,
    pub name: String,
}

fn normalized_host(target: &str) -> Option<String> {
    let target = target.trim();
    if target.is_empty() {
        return None;
    }
    if let Ok(addr) = target.parse::<SocketAddr>() {
        return match addr.ip() {
            IpAddr::V4(ip) => Some(ip.to_string()),
            IpAddr::V6(_) => None,
        };
    }
    if let Ok(ip) = target.parse::<Ipv4Addr>() {
        return Some(ip.to_string());
    }
    let host = match target.rsplit_once(':') {
        Some((host, port)) if port.parse::<u16>().is_ok() => host,
        Some(_) => return None,
        None => target,
    };
    let host = host.trim_end_matches('.');
    if host.is_empty()
        || host.contains(char::is_whitespace)
        || host.parse::<std::net::Ipv6Addr>().is_ok()
    {
        return None;
    }
    Some(host.to_ascii_lowercase())
}

pub fn is_target(target: &str) -> bool {
    let configured = Config::get_option(keys::OPTION_FORCE_DIRECT_SERVER);
    let Some(target) = normalized_host(target) else {
        return false;
    };
    configured
        .split(',')
        .filter_map(normalized_host)
        .any(|configured| configured == target)
}

/// Replaces a configured direct-server hostname with the configured IPv4
/// alias while preserving its port. This avoids depending on a VPN-controlled
/// DNS path after the physical interface has explicitly been selected.
///
/// The replacement is intentionally enabled only when the direct-server list
/// contains exactly one IPv4 alias. With zero or multiple aliases there is no
/// unambiguous hostname-to-address mapping, so normal DNS resolution is kept.
fn resolved_target_from_config(target: &str, configured: &str) -> Option<String> {
    let Some(target_host) = normalized_host(target) else {
        return None;
    };
    if !configured
        .split(',')
        .filter_map(normalized_host)
        .any(|configured| configured == target_host)
    {
        return None;
    }

    let mut aliases = configured
        .split(',')
        .filter_map(normalized_host)
        .filter_map(|host| host.parse::<Ipv4Addr>().ok())
        .collect::<Vec<_>>();
    aliases.sort_unstable();
    aliases.dedup();
    if aliases.len() != 1 {
        return None;
    }

    if target_host.parse::<Ipv4Addr>().is_ok() {
        return Some(target.to_owned());
    }

    let alias = aliases[0];
    match target.rsplit_once(':') {
        Some((_, port)) if port.parse::<u16>().is_ok() => Some(format!("{alias}:{port}")),
        Some(_) => None,
        None => Some(alias.to_string()),
    }
}

pub fn resolved_target(target: &str) -> Option<String> {
    resolved_target_from_config(
        target,
        &Config::get_option(keys::OPTION_FORCE_DIRECT_SERVER),
    )
}

#[cfg(target_os = "windows")]
fn is_hyper_v_external_ethernet(description: Option<&str>) -> bool {
    description.map_or(false, |description| {
        description
            .to_ascii_lowercase()
            .contains("hyper-v virtual ethernet adapter")
    })
}

#[cfg(target_os = "windows")]
fn is_usable_egress_interface(index: u32, description: Option<&str>) -> bool {
    use winapi::shared::{
        ifdef::IfOperStatusUp,
        ipifcons::{IF_TYPE_ETHERNET_CSMACD, IF_TYPE_TUNNEL},
        netioapi::{GetIfEntry2, MIB_IF_ROW2},
    };

    // GetIfEntry2 requires a zeroed row with either InterfaceLuid or
    // InterfaceIndex initialized.
    let mut row: MIB_IF_ROW2 = unsafe { std::mem::zeroed() };
    row.InterfaceIndex = index;
    if unsafe { GetIfEntry2(&mut row) } != 0 {
        return false;
    }

    let hardware_or_external_hyper_v = row.InterfaceAndOperStatusFlags.HardwareInterface() != 0
        || (row.Type == IF_TYPE_ETHERNET_CSMACD && is_hyper_v_external_ethernet(description));

    row.OperStatus == IfOperStatusUp
        && row.Type != IF_TYPE_TUNNEL
        && row.InterfaceAndOperStatusFlags.NotMediaConnected() == 0
        && row.InterfaceAndOperStatusFlags.EndPointInterface() == 0
        && hardware_or_external_hyper_v
}

#[cfg(target_os = "windows")]
pub fn interfaces() -> Vec<DirectInterface> {
    network_interface::get_interfaces()
        .into_iter()
        .filter(|interface| interface.gateway.is_some())
        .filter(|interface| {
            is_usable_egress_interface(interface.index, interface.description.as_deref())
        })
        .filter_map(|interface| {
            let local_ip = interface
                .ipv4
                .iter()
                .map(|network| network.addr)
                .find(|ip| !ip.is_unspecified() && !ip.is_loopback() && !ip.is_link_local())?;
            let name = interface
                .friendly_name
                .filter(|name| !name.is_empty())
                .unwrap_or(interface.name);
            Some(DirectInterface {
                index: interface.index,
                local_ip,
                name,
            })
        })
        .collect()
}

#[cfg(not(target_os = "windows"))]
pub fn interfaces() -> Vec<DirectInterface> {
    Vec::new()
}

#[cfg(target_os = "windows")]
pub fn interface_for_local_ip(local_ip: IpAddr) -> Option<DirectInterface> {
    let IpAddr::V4(local_ip) = local_ip else {
        return None;
    };
    interfaces()
        .into_iter()
        .find(|interface| interface.local_ip == local_ip)
}

#[cfg(target_os = "windows")]
pub fn set_ipv4_unicast_interface(
    socket: &impl std::os::windows::io::AsRawSocket,
    interface_index: u32,
) -> std::io::Result<()> {
    use std::{mem::size_of, os::raw::c_char};
    use winapi::{
        shared::ws2def::IPPROTO_IP,
        um::winsock2::{setsockopt, SOCKET_ERROR},
    };

    // IP_UNICAST_IF is 31 in the Windows SDK.  Unlike IPV6_UNICAST_IF,
    // the IPv4 interface index must be passed in network byte order.
    const IP_UNICAST_IF: i32 = 31;
    let interface_index = interface_index.to_be();
    let result = unsafe {
        setsockopt(
            socket.as_raw_socket() as _,
            IPPROTO_IP,
            IP_UNICAST_IF,
            &interface_index as *const u32 as *const c_char,
            size_of::<u32>() as i32,
        )
    };
    if result == SOCKET_ERROR {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_only_the_compiled_direct_targets() {
        crate::config::DEFAULT_SETTINGS.write().unwrap().insert(
            keys::OPTION_FORCE_DIRECT_SERVER.to_owned(),
            "desk.masteronline.space,176.123.167.146".to_owned(),
        );

        assert!(is_target("desk.masteronline.space"));
        assert!(is_target("DESK.MASTERONLINE.SPACE:21116"));
        assert!(is_target("desk.masteronline.space.:21117"));
        assert!(is_target("176.123.167.146"));
        assert!(is_target("176.123.167.146:21116"));
        assert!(is_target("176.123.167.146:21117"));
        assert!(!is_target("176.123.167.147:21116"));
        assert!(!is_target("example.com:21116"));
    }

    #[test]
    fn resolves_configured_hostnames_to_the_single_ipv4_alias() {
        let configured = "hbbs.masterdesk.online,hbbr.masterdesk.online,176.123.167.146";

        assert_eq!(
            resolved_target_from_config("hbbs.masterdesk.online:21116", configured),
            Some("176.123.167.146:21116".to_owned())
        );
        assert_eq!(
            resolved_target_from_config("hbbr.masterdesk.online:21117", configured),
            Some("176.123.167.146:21117".to_owned())
        );
        assert_eq!(
            resolved_target_from_config("example.com:21116", configured),
            None
        );
    }

    #[test]
    fn leaves_dns_in_control_when_the_ipv4_alias_is_ambiguous() {
        let configured = "hbbs.masterdesk.online,176.123.167.146,176.123.167.147";

        assert_eq!(
            resolved_target_from_config("hbbs.masterdesk.online:21116", configured),
            None
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn recognizes_only_hyper_v_virtual_ethernet_as_external_fallback() {
        assert!(is_hyper_v_external_ethernet(Some(
            "Hyper-V Virtual Ethernet Adapter #2"
        )));
        assert!(!is_hyper_v_external_ethernet(Some("sing-tun Tunnel")));
        assert!(!is_hyper_v_external_ethernet(Some(
            "TAP-Windows Adapter V9"
        )));
    }
}
