/// WebSocket connection utilities for extracting real client IP and connection parameters

use anyhow::{anyhow, Result};
use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::AsRawFd;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::handshake::server::Request;

/// Connection parameters extracted from TCP socket
#[derive(Debug, Clone)]
pub struct ConnectionParams {
    pub local_ip: Ipv4Addr,
    pub local_port: u16,
    pub peer_port: u16,
}

/// Extract real client IP from proxy headers (X-Forwarded-For or X-Real-IP)
pub fn extract_real_client_ip(
    request: &Request,
    fallback_peer: SocketAddr,
) -> Ipv4Addr {
    // Try X-Forwarded-For header first (can contain multiple IPs: "client, proxy1, proxy2")
    if let Some(forwarded_header) = request.headers().get("X-Forwarded-For") {
        if let Ok(forwarded_str) = forwarded_header.to_str() {
            // Take the first IP (real client)
            if let Some(client_ip_str) = forwarded_str.split(',').next() {
                if let Ok(ip) = client_ip_str.trim().parse::<Ipv4Addr>() {
                    eprintln!("[DEBUG connection] Real client IP from X-Forwarded-For: {}", ip);
                    return ip;
                }
            }
        }
    }
    
    // Try X-Real-IP header
    if let Some(real_ip_header) = request.headers().get("X-Real-IP") {
        if let Ok(ip_str) = real_ip_header.to_str() {
            if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                eprintln!("[DEBUG connection] Real client IP from X-Real-IP: {}", ip);
                return ip;
            }
        }
    }
    
    // Fallback to peer address (likely proxy IP if behind reverse proxy)
    eprintln!("[DEBUG connection] No proxy headers found, using peer IP: {}", fallback_peer.ip());
    match fallback_peer.ip() {
        std::net::IpAddr::V4(ip) => {
            eprintln!("[DEBUG connection] WARNING: Using peer IP {} (likely proxy!)", ip);
            ip
        }
        std::net::IpAddr::V6(_) => {
            eprintln!("[DEBUG connection] ERROR: IPv6 not supported, using 0.0.0.0");
            Ipv4Addr::new(0, 0, 0, 0)
        }
    }
}

/// Extract connection parameters from WebSocket TCP stream using getsockname/getpeername
pub fn extract_connection_params(stream: &TcpStream) -> Result<ConnectionParams> {
    let socket_fd = stream.as_raw_fd();
    
    unsafe {
        // Get local address (server side)
        let mut local_addr: libc::sockaddr_storage = std::mem::zeroed();
        let mut local_len: libc::socklen_t = std::mem::size_of::<libc::sockaddr_storage>() as u32;
        
        let result = libc::getsockname(
            socket_fd,
            &mut local_addr as *mut _ as *mut libc::sockaddr,
            &mut local_len,
        );
        
        if result != 0 {
            return Err(anyhow!("getsockname failed"));
        }
        
        // Get peer address (client side)
        let mut peer_addr: libc::sockaddr_storage = std::mem::zeroed();
        let mut peer_len: libc::socklen_t = std::mem::size_of::<libc::sockaddr_storage>() as u32;
        
        let result = libc::getpeername(
            socket_fd,
            &mut peer_addr as *mut _ as *mut libc::sockaddr,
            &mut peer_len,
        );
        
        if result != 0 {
            return Err(anyhow!("getpeername failed"));
        }
        
        // Parse sockaddr_in structures
        let local_sockaddr = &*((&local_addr) as *const _ as *const libc::sockaddr_in);
        let local_ip = Ipv4Addr::from(u32::from_be(local_sockaddr.sin_addr.s_addr));
        let local_port = u16::from_be(local_sockaddr.sin_port);
        
        let peer_sockaddr = &*((&peer_addr) as *const _ as *const libc::sockaddr_in);
        let _peer_ip = Ipv4Addr::from(u32::from_be(peer_sockaddr.sin_addr.s_addr));
        let peer_port = u16::from_be(peer_sockaddr.sin_port);
        
        Ok(ConnectionParams {
            local_ip,
            local_port,
            peer_port,
        })
    }
}
