/// Raw socket operations for sending TCP probes and receiving ICMP responses

use anyhow::{anyhow, Result};
use libc::{
    bind, close, htons, if_nametoindex, recvfrom, sendto, setsockopt, socket,
    sockaddr_in, sockaddr_ll, AF_INET, AF_PACKET, IPPROTO_RAW, SOCK_RAW,
    IP_HDRINCL, SOL_IP, ETH_P_IP, c_int, c_void,
};
use std::net::Ipv4Addr;
use std::os::fd::RawFd;
use crate::constants::*;
use crate::icmp::{check_icmp_for_any_id, parse_icmp_time_exceeded, HopInfo};
use crate::packet::{build_ip_header, build_tcp_header, calculate_tcp_checksum, generate_sequence_number};

/// Create a raw IP socket for sending custom TCP packets with specific TTL
pub fn create_raw_socket() -> Result<RawFd> {
    let socket_fd = unsafe { socket(AF_INET, SOCK_RAW, IPPROTO_RAW) };
    
    if socket_fd < 0 {
        return Err(std::io::Error::last_os_error()).map_err(|e| anyhow!(e));
    }
    
    // Enable IP_HDRINCL so we can craft our own IP headers (including TTL)
    let enable: c_int = 1;
    let result = unsafe {
        setsockopt(
            socket_fd,
            SOL_IP,
            IP_HDRINCL,
            &enable as *const _ as *const c_void,
            std::mem::size_of::<c_int>() as u32,
        )
    };
    
    if result != 0 {
        unsafe { close(socket_fd) };
        return Err(std::io::Error::last_os_error()).map_err(|e| anyhow!(e));
    }
    
    eprintln!("[DEBUG network] Created raw IP socket fd={}", socket_fd);
    Ok(socket_fd)
}

/// Create a packet capture socket (AF_PACKET) for receiving ICMP packets
pub fn create_icmp_socket() -> Result<RawFd> {
    let socket_fd = unsafe { socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP as u16) as i32) };
    
    if socket_fd < 0 {
        return Err(std::io::Error::last_os_error()).map_err(|e| anyhow!(e));
    }
    
    // Bind to network interface
    bind_to_interface(socket_fd, DEFAULT_INTERFACE_NAME);
    
    // Set receive buffer size
    set_socket_recv_buffer(socket_fd, DEFAULT_SOCKET_RECV_BUFFER_SIZE);
    
    eprintln!("[DEBUG network] Created AF_PACKET socket fd={} (link-layer capture)", socket_fd);
    Ok(socket_fd)
}

/// Bind socket to specific network interface
fn bind_to_interface(socket_fd: RawFd, interface_name: &str) {
    let ifname_cstr = format!("{}\0", interface_name);
    let interface_index = unsafe {
        if_nametoindex(ifname_cstr.as_ptr() as *const libc::c_char)
    };
    
    if interface_index == 0 {
        eprintln!("[DEBUG network] Warning: Interface {} not found, will receive from all interfaces", interface_name);
        return;
    }
    
    let mut socket_addr: sockaddr_ll = unsafe { std::mem::zeroed() };
    socket_addr.sll_family = AF_PACKET as u16;
    socket_addr.sll_protocol = htons(ETH_P_IP as u16);
    socket_addr.sll_ifindex = interface_index as i32;
    socket_addr.sll_pkttype = 0; // PACKET_HOST
    
    let result = unsafe {
        bind(
            socket_fd,
            &socket_addr as *const sockaddr_ll as *const libc::sockaddr,
            std::mem::size_of::<sockaddr_ll>() as u32,
        )
    };
    
    if result < 0 {
        let error = std::io::Error::last_os_error();
        eprintln!("[DEBUG network] Warning: Failed to bind to {}: {}", interface_name, error);
    } else {
        eprintln!("[DEBUG network] Bound to {} (interface index={})", interface_name, interface_index);
    }
}

/// Set socket receive buffer size
fn set_socket_recv_buffer(socket_fd: RawFd, buffer_size: c_int) {
    let result = unsafe {
        setsockopt(
            socket_fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &buffer_size as *const _ as *const c_void,
            std::mem::size_of::<c_int>() as u32,
        )
    };
    
    if result < 0 {
        eprintln!("[DEBUG network] Warning: Failed to set SO_RCVBUF to {} bytes", buffer_size);
    } else {
        eprintln!("[DEBUG network] Set receive buffer to {} bytes", buffer_size);
    }
}

/// Send a TCP probe packet with specified TTL
/// Returns the IP ID of the sent packet for matching with ICMP responses
pub fn send_tcp_probe(
    socket_fd: RawFd,
    source_ip: Ipv4Addr,
    dest_ip: Ipv4Addr,
    source_port: u16,
    dest_port: u16,
    ttl: u8,
    sequence_base: u32,
) -> Result<u16> {
    eprintln!(
        "[DEBUG network] Sending TCP probe: {}:{} -> {}:{} TTL={}",
        source_ip, source_port, dest_ip, dest_port, ttl
    );
    
    const TOTAL_LENGTH: u16 = (IP_HEADER_LEN + TCP_HEADER_LEN) as u16;
    let mut packet = [0u8; TOTAL_LENGTH as usize];
    
    // Build IP header
    let (ip_header, packet_id) = build_ip_header(source_ip, dest_ip, ttl, TOTAL_LENGTH);
    packet[..IP_HEADER_LEN].copy_from_slice(&ip_header);
    
    // Build TCP header
    let sequence_number = generate_sequence_number(sequence_base + ttl as u32);
    let mut tcp_header = build_tcp_header(source_port, dest_port, sequence_number);
    
    // Calculate TCP checksum
    let tcp_checksum = calculate_tcp_checksum(&ip_header, &tcp_header);
    tcp_header[16..18].copy_from_slice(&tcp_checksum.to_be_bytes());
    
    packet[IP_HEADER_LEN..].copy_from_slice(&tcp_header);
    
    // Send packet
    let dest_sockaddr = sockaddr_in {
        sin_family: AF_INET as u16,
        sin_port: 0, // Ignored with IPPROTO_RAW
        sin_addr: libc::in_addr {
            s_addr: u32::from(dest_ip).to_be(),
        },
        sin_zero: [0; 8],
    };
    
    let bytes_sent = unsafe {
        sendto(
            socket_fd,
            packet.as_ptr() as *const c_void,
            packet.len(),
            0,
            &dest_sockaddr as *const sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<sockaddr_in>() as u32,
        )
    };
    
    if bytes_sent < 0 {
        let error = std::io::Error::last_os_error();
        eprintln!("[DEBUG network] sendto failed: {}", error);
        return Err(error).map_err(|e| anyhow!(e));
    }
    
    eprintln!("[DEBUG network] Sent {} bytes, IP ID={}", bytes_sent, packet_id);
    Ok(packet_id)
}

/// Poll ICMP socket for Time Exceeded messages matching any expected IP ID
/// Returns (IP ID, HopInfo) if a matching ICMP is found, None if timeout
pub async fn poll_icmp_responses(
    socket_fd: RawFd,
    expected_ip_ids: &std::collections::HashMap<u16, u8>,
    timeout_ms: u64,
) -> Result<Option<(u16, HopInfo)>> {
    let expected_map = expected_ip_ids.clone();
    
    let result = tokio::task::spawn_blocking(move || {
        eprintln!(
            "[DEBUG network] Polling for ICMP matching any of {} IP IDs (timeout={}ms)",
            expected_map.len(),
            timeout_ms
        );
        
        // Set socket receive timeout
        set_receive_timeout(socket_fd, timeout_ms);
        
        let mut buffer = [0u8; PACKET_BUFFER_SIZE];
        let mut src_addr: sockaddr_in = unsafe { std::mem::zeroed() };
        let mut addr_len: libc::socklen_t = std::mem::size_of::<sockaddr_in>() as u32;
        
        // Build set of expected IP IDs for fast lookup
        let expected_ids: std::collections::HashSet<u16> = expected_map.keys().copied().collect();
        
        // Try to receive ICMP packets
        for _attempt in 1..=MAX_ICMP_RECEIVE_ATTEMPTS {
            let bytes_received = unsafe {
                recvfrom(
                    socket_fd,
                    buffer.as_mut_ptr() as *mut c_void,
                    buffer.len(),
                    0,
                    &mut src_addr as *mut _ as *mut libc::sockaddr,
                    &mut addr_len,
                )
            };
            
            if bytes_received < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut
                {
                    return Ok(None); // Timeout
                }
                return Err(error);
            }
            
            let packet_size = bytes_received as usize;
            
            // Check if this ICMP matches any of our expected IP IDs
            if let Some(matched_id) = check_icmp_for_any_id(&buffer, packet_size, &expected_ids) {
                if let Some(&sent_ttl) = expected_map.get(&matched_id) {
                    eprintln!(
                        "[DEBUG network] Found ICMP match for IP ID {} (TTL={})",
                        matched_id, sent_ttl
                    );
                    
                    // Parse full hop information
                    if let Some((router_ip, mpls_labels, modifications)) =
                        parse_icmp_time_exceeded(&buffer, packet_size, matched_id, sent_ttl)
                    {
                        return Ok(Some((
                            matched_id,
                            HopInfo {
                                router_ip: router_ip.to_string(),
                                mpls_labels,
                                modifications,
                            },
                        )));
                    }
                }
            }
        }
        
        Ok(None)
    })
    .await?;

    result.map_err(|e| anyhow!(e))
}

/// Set socket receive timeout
fn set_receive_timeout(socket_fd: RawFd, timeout_ms: u64) {
    let timeout_seconds = (timeout_ms / 1000) as i64;
    let timeout_microseconds = ((timeout_ms % 1000) * 1000) as i64;
    
    let timeout_val = libc::timeval {
        tv_sec: timeout_seconds,
        tv_usec: timeout_microseconds,
    };
    
    let result = unsafe {
        libc::setsockopt(
            socket_fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &timeout_val as *const _ as *const c_void,
            std::mem::size_of::<libc::timeval>() as u32,
        )
    };
    
    if result < 0 {
        eprintln!("[DEBUG network] Failed to set SO_RCVTIMEO");
    } else {
        eprintln!(
            "[DEBUG network] Socket timeout set to {}.{:03}s",
            timeout_seconds, timeout_ms % 1000
        );
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_network_module_compiles() {
        // Verify module compiles
    }
}
