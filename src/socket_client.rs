#[cfg(feature = "webrtc")]
use crate::webrtc::{self, is_webrtc_endpoint};
use crate::{
    config::{Config, NetworkType},
    tcp::FramedStream,
    udp::FramedSocket,
    websocket::{self, check_ws, is_ws_endpoint},
    ResultType, Stream,
};
use anyhow::Context;
#[cfg(target_os = "windows")]
use futures::stream::{FuturesUnordered, StreamExt};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use tokio::net::{ToSocketAddrs, UdpSocket};
use tokio_socks::{IntoTargetAddr, TargetAddr};

#[cfg(target_os = "windows")]
async fn direct_interfaces() -> ResultType<Vec<crate::direct_server::DirectInterface>> {
    let interfaces = tokio::task::spawn_blocking(crate::direct_server::interfaces)
        .await
        .context("Direct-server bypass failed to enumerate Windows interfaces")?;
    if interfaces.is_empty() {
        anyhow::bail!(
            "Direct-server bypass found no connected physical or external Hyper-V IPv4 interface with a gateway"
        );
    }
    Ok(interfaces)
}

#[cfg(target_os = "windows")]
async fn connect_tcp_direct_server(target: String, ms_timeout: u64) -> ResultType<FramedStream> {
    let interfaces = direct_interfaces().await?;
    let resolved_target =
        crate::direct_server::resolved_target(&target).unwrap_or_else(|| target.clone());
    if resolved_target != target {
        log::info!(
            "Direct-server bypass resolved {target} to compiled IPv4 alias {resolved_target}"
        );
    }
    let mut attempts = FuturesUnordered::new();
    for interface in interfaces {
        let target = resolved_target.clone();
        attempts.push(async move {
            let local_addr = SocketAddr::new(IpAddr::V4(interface.local_ip), 0);
            let result =
                FramedStream::new_on_interface(target, local_addr, interface.index, ms_timeout)
                    .await;
            (interface, result)
        });
    }

    let mut failures = Vec::new();
    while let Some((interface, result)) = attempts.next().await {
        match result {
            Ok(stream) => {
                log::info!(
                    "Direct-server bypass connected through direct interface '{}' (index {}, {})",
                    interface.name,
                    interface.index,
                    interface.local_ip
                );
                return Ok(stream);
            }
            Err(err) => failures.push(format!(
                "{} (index {}): {err}",
                interface.name, interface.index
            )),
        }
    }

    anyhow::bail!(
        "Direct-server bypass failed to connect to {target}: {}",
        failures.join("; ")
    )
}

#[cfg(target_os = "windows")]
async fn direct_udp_route(
    target: &str,
) -> ResultType<Option<(crate::direct_server::DirectInterface, SocketAddr)>> {
    if !crate::direct_server::is_target(target) {
        return Ok(None);
    }
    let resolved_target =
        crate::direct_server::resolved_target(target).unwrap_or_else(|| target.to_owned());
    let peer_addr = tokio::net::lookup_host(&resolved_target)
        .await?
        .find(SocketAddr::is_ipv4)
        .context(format!(
            "Direct-server bypass failed to resolve an IPv4 address for {target}"
        ))?;
    let interface = direct_interfaces()
        .await?
        .into_iter()
        .next()
        .context("Direct-server bypass found no direct interface")?;
    log::info!(
        "Direct-server bypass selected direct interface '{}' (index {}, {}) for UDP",
        interface.name,
        interface.index,
        interface.local_ip
    );
    Ok(Some((interface, peer_addr)))
}

#[inline]
pub fn check_port<T: std::string::ToString>(host: T, port: i32) -> String {
    let host = host.to_string();
    if crate::is_ipv6_str(&host) {
        if host.starts_with('[') {
            return host;
        }
        return format!("[{host}]:{port}");
    }
    if !host.contains(':') {
        return format!("{host}:{port}");
    }
    host
}

#[inline]
pub fn increase_port<T: std::string::ToString>(host: T, offset: i32) -> String {
    let host = host.to_string();
    if crate::is_ipv6_str(&host) {
        if host.starts_with('[') {
            let tmp: Vec<&str> = host.split("]:").collect();
            if tmp.len() == 2 {
                let port: i32 = tmp[1].parse().unwrap_or(0);
                if port > 0 {
                    return format!("{}]:{}", tmp[0], port + offset);
                }
            }
        }
    } else if host.contains(':') {
        let tmp: Vec<&str> = host.split(':').collect();
        if tmp.len() == 2 {
            let port: i32 = tmp[1].parse().unwrap_or(0);
            if port > 0 {
                return format!("{}:{}", tmp[0], port + offset);
            }
        }
    }
    host
}

pub fn split_host_port<T: std::string::ToString>(host: T) -> Option<(String, i32)> {
    let host = host.to_string();
    if crate::is_ipv6_str(&host) {
        if host.starts_with('[') {
            let tmp: Vec<&str> = host.split("]:").collect();
            if tmp.len() == 2 {
                let port: i32 = tmp[1].parse().unwrap_or(0);
                if port > 0 {
                    return Some((format!("{}]", tmp[0]), port));
                }
            }
        }
    } else if host.contains(':') {
        let tmp: Vec<&str> = host.split(':').collect();
        if tmp.len() == 2 {
            let port: i32 = tmp[1].parse().unwrap_or(0);
            if port > 0 {
                return Some((tmp[0].to_string(), port));
            }
        }
    }
    None
}

pub fn test_if_valid_server(host: &str, test_with_proxy: bool) -> String {
    let host = check_port(host, 0);
    use std::net::ToSocketAddrs;

    if test_with_proxy && NetworkType::ProxySocks == Config::get_network_type() {
        test_if_valid_server_for_proxy_(&host)
    } else {
        match host.to_socket_addrs() {
            Err(err) => err.to_string(),
            Ok(_) => "".to_owned(),
        }
    }
}

#[inline]
pub fn test_if_valid_server_for_proxy_(host: &str) -> String {
    // `&host.into_target_addr()` is defined in `tokio-socs`, but is a common pattern for testing,
    // it can be used for both `socks` and `http` proxy.
    match &host.into_target_addr() {
        Err(err) => err.to_string(),
        Ok(_) => "".to_owned(),
    }
}

pub trait IsResolvedSocketAddr {
    fn resolve(&self) -> Option<&SocketAddr>;
}

impl IsResolvedSocketAddr for SocketAddr {
    fn resolve(&self) -> Option<&SocketAddr> {
        Some(self)
    }
}

impl IsResolvedSocketAddr for String {
    fn resolve(&self) -> Option<&SocketAddr> {
        None
    }
}

impl IsResolvedSocketAddr for &str {
    fn resolve(&self) -> Option<&SocketAddr> {
        None
    }
}

// This function checks if the target is a websocket endpoint and connects accordingly.
#[inline]
pub async fn connect_tcp<
    't,
    T: IntoTargetAddr<'t> + ToSocketAddrs + IsResolvedSocketAddr + std::fmt::Display,
>(
    target: T,
    ms_timeout: u64,
) -> ResultType<crate::Stream> {
    #[cfg(feature = "webrtc")]
    if is_webrtc_endpoint(&target.to_string()) {
        return Ok(Stream::WebRTC(
            webrtc::WebRTCStream::new(&target.to_string(), false, ms_timeout).await?,
        ));
    }
    let target_str = check_ws(&target.to_string());
    if is_ws_endpoint(&target_str) {
        return Ok(Stream::WebSocket(
            websocket::WsFramedStream::new(target_str, None, None, ms_timeout).await?,
        ));
    }
    connect_tcp_local(target, None, ms_timeout).await
}

// This function connects directly to the target without checking for websocket endpoints.
pub async fn connect_tcp_local<
    't,
    T: IntoTargetAddr<'t> + ToSocketAddrs + IsResolvedSocketAddr + std::fmt::Display,
>(
    target: T,
    local: Option<SocketAddr>,
    ms_timeout: u64,
) -> ResultType<Stream> {
    let target_string = target.to_string();

    #[cfg(target_os = "windows")]
    if crate::direct_server::is_target(&target_string) {
        return Ok(Stream::Tcp(
            connect_tcp_direct_server(target_string, ms_timeout).await?,
        ));
    }

    // A TCP hole-punch attempt reuses the physical local address of the
    // server socket. Keep that peer socket on the same physical interface
    // instead of allowing Windows to route it back through a TUN adapter.
    #[cfg(target_os = "windows")]
    if let Some(local_addr) = local {
        let local_ip = local_addr.ip();
        let interface = tokio::task::spawn_blocking(move || {
            crate::direct_server::interface_for_local_ip(local_ip)
        })
        .await
        .context("Direct-server bypass failed to inspect the local Windows interface")?;
        if let Some(interface) = interface {
            return Ok(Stream::Tcp(
                FramedStream::new_on_interface(
                    target_string,
                    local_addr,
                    interface.index,
                    ms_timeout,
                )
                .await?,
            ));
        }
    }

    if let Some(conf) = Config::get_socks() {
        return Ok(Stream::Tcp(
            FramedStream::connect(target, local, &conf, ms_timeout).await?,
        ));
    }

    if let Some(target_addr) = target.resolve() {
        if let Some(local_addr) = local {
            if local_addr.is_ipv6() && target_addr.is_ipv4() {
                let resolved_target = query_nip_io(target_addr).await?;
                return Ok(Stream::Tcp(
                    FramedStream::new(resolved_target, Some(local_addr), ms_timeout).await?,
                ));
            }
        }
    }

    Ok(Stream::Tcp(
        FramedStream::new(target, local, ms_timeout).await?,
    ))
}

#[inline]
pub fn is_ipv4(target: &TargetAddr<'_>) -> bool {
    match target {
        TargetAddr::Ip(addr) => addr.is_ipv4(),
        _ => true,
    }
}

#[inline]
pub async fn query_nip_io(addr: &SocketAddr) -> ResultType<SocketAddr> {
    tokio::net::lookup_host(format!("{}.nip.io:{}", addr.ip(), addr.port()))
        .await?
        .find(|x| x.is_ipv6())
        .context("Failed to get ipv6 from nip.io")
}

#[inline]
pub fn ipv4_to_ipv6(addr: String, ipv4: bool) -> String {
    if !ipv4 && crate::is_ipv4_str(&addr) {
        if let Some(ip) = addr.split(':').next() {
            return addr.replace(ip, &format!("{ip}.nip.io"));
        }
    }
    addr
}

async fn test_target(target: &str) -> ResultType<SocketAddr> {
    if let Ok(Ok(s)) = super::timeout(1000, tokio::net::TcpStream::connect(target)).await {
        if let Ok(addr) = s.peer_addr() {
            return Ok(addr);
        }
    }
    tokio::net::lookup_host(target)
        .await?
        .next()
        .context(format!("Failed to look up host for {target}"))
}

#[inline]
pub async fn new_direct_udp_for(target: &str) -> ResultType<(Arc<UdpSocket>, SocketAddr)> {
    #[cfg(target_os = "windows")]
    if let Some((interface, peer_addr)) = direct_udp_route(target).await? {
        let local_addr = SocketAddr::new(IpAddr::V4(interface.local_ip), 0);
        let socket = crate::udp::new_udp_socket_on_interface(local_addr, interface.index)?;
        return Ok((Arc::new(socket), peer_addr));
    }

    let peer_addr = test_target(target).await?;
    let local_addr = Config::get_any_listen_addr(peer_addr.is_ipv4());
    let socket = UdpSocket::bind(local_addr).await?;
    Ok((Arc::new(socket), peer_addr))
}

#[inline]
pub async fn new_udp_for(
    target: &str,
    ms_timeout: u64,
) -> ResultType<(FramedSocket, TargetAddr<'static>)> {
    #[cfg(target_os = "windows")]
    if let Some((interface, peer_addr)) = direct_udp_route(target).await? {
        let local_addr = SocketAddr::new(IpAddr::V4(interface.local_ip), 0);
        return Ok((
            FramedSocket::new_on_interface(local_addr, interface.index)?,
            peer_addr.into_target_addr()?.to_owned(),
        ));
    }

    let (ipv4, target) = if NetworkType::Direct == Config::get_network_type() {
        let addr = test_target(target).await?;
        (addr.is_ipv4(), addr.into_target_addr()?)
    } else {
        (true, target.into_target_addr()?)
    };
    Ok((
        new_udp(Config::get_any_listen_addr(ipv4), ms_timeout).await?,
        target.to_owned(),
    ))
}

async fn new_udp<T: ToSocketAddrs>(local: T, ms_timeout: u64) -> ResultType<FramedSocket> {
    match Config::get_socks() {
        None => Ok(FramedSocket::new(local).await?),
        Some(conf) => {
            let socket = FramedSocket::new_proxy(
                conf.proxy.as_str(),
                local,
                conf.username.as_str(),
                conf.password.as_str(),
                ms_timeout,
            )
            .await?;
            Ok(socket)
        }
    }
}

pub async fn rebind_udp_for(
    target: &str,
) -> ResultType<Option<(FramedSocket, TargetAddr<'static>)>> {
    #[cfg(target_os = "windows")]
    if let Some((interface, peer_addr)) = direct_udp_route(target).await? {
        let local_addr = SocketAddr::new(IpAddr::V4(interface.local_ip), 0);
        return Ok(Some((
            FramedSocket::new_on_interface(local_addr, interface.index)?,
            peer_addr.into_target_addr()?.to_owned(),
        )));
    }

    if Config::get_network_type() != NetworkType::Direct {
        return Ok(None);
    }
    let addr = test_target(target).await?;
    let v4 = addr.is_ipv4();
    Ok(Some((
        FramedSocket::new(Config::get_any_listen_addr(v4)).await?,
        addr.into_target_addr()?.to_owned(),
    )))
}

#[cfg(test)]
mod tests {
    use std::net::ToSocketAddrs;

    use super::*;

    #[test]
    fn test_nat64() {
        test_nat64_async();
    }

    #[tokio::main(flavor = "current_thread")]
    async fn test_nat64_async() {
        assert_eq!(ipv4_to_ipv6("1.1.1.1".to_owned(), true), "1.1.1.1");
        assert_eq!(ipv4_to_ipv6("1.1.1.1".to_owned(), false), "1.1.1.1.nip.io");
        assert_eq!(
            ipv4_to_ipv6("1.1.1.1:8080".to_owned(), false),
            "1.1.1.1.nip.io:8080"
        );
        assert_eq!(
            ipv4_to_ipv6("rustdesk.com".to_owned(), false),
            "rustdesk.com"
        );
        if ("rustdesk.com:80")
            .to_socket_addrs()
            .unwrap()
            .next()
            .unwrap()
            .is_ipv6()
        {
            assert!(query_nip_io(&"1.1.1.1:80".parse().unwrap())
                .await
                .unwrap()
                .is_ipv6());
            return;
        }
        assert!(query_nip_io(&"1.1.1.1:80".parse().unwrap()).await.is_err());
    }

    #[test]
    fn test_test_if_valid_server() {
        assert!(!test_if_valid_server("a", false).is_empty());
        // on Linux, "1" is resolved to "0.0.0.1"
        assert!(test_if_valid_server("1.1.1.1", false).is_empty());
        assert!(test_if_valid_server("1.1.1.1:1", false).is_empty());
        assert!(test_if_valid_server("microsoft.com", false).is_empty());
        assert!(test_if_valid_server("microsoft.com:1", false).is_empty());

        // with proxy
        // `:0` indicates `let host = check_port(host, 0);` is called.
        assert!(test_if_valid_server_for_proxy_("a:0").is_empty());
        assert!(test_if_valid_server_for_proxy_("1.1.1.1:0").is_empty());
        assert!(test_if_valid_server_for_proxy_("1.1.1.1:1").is_empty());
        assert!(test_if_valid_server_for_proxy_("abc.com:0").is_empty());
        assert!(test_if_valid_server_for_proxy_("abcd.com:1").is_empty());
    }

    #[test]
    fn test_check_port() {
        assert_eq!(check_port("[1:2]:12", 32), "[1:2]:12");
        assert_eq!(check_port("1:2", 32), "[1:2]:32");
        assert_eq!(check_port("z1:2", 32), "z1:2");
        assert_eq!(check_port("1.1.1.1", 32), "1.1.1.1:32");
        assert_eq!(check_port("1.1.1.1:32", 32), "1.1.1.1:32");
        assert_eq!(check_port("test.com:32", 0), "test.com:32");
        assert_eq!(increase_port("[1:2]:12", 1), "[1:2]:13");
        assert_eq!(increase_port("1.2.2.4:12", 1), "1.2.2.4:13");
        assert_eq!(increase_port("1.2.2.4", 1), "1.2.2.4");
        assert_eq!(increase_port("test.com", 1), "test.com");
        assert_eq!(increase_port("test.com:13", 4), "test.com:17");
        assert_eq!(increase_port("1:13", 4), "1:13");
        assert_eq!(increase_port("22:1:13", 4), "22:1:13");
        assert_eq!(increase_port("z1:2", 1), "z1:3");
    }
}
