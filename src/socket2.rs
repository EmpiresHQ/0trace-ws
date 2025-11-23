use anyhow::{anyhow, Result};
use std::os::fd::RawFd;
use std::net::Ipv4Addr;
use libc::{
    c_int, c_void, recvfrom, sendto, setsockopt,
    sockaddr_in, socket, close, AF_INET, IPPROTO_RAW, IPPROTO_TCP, IPPROTO_ICMP, SOCK_RAW,
    IP_HDRINCL, SOL_IP,
};

// ICMP constants
const ICMP_TIME_EXCEEDED: u8 = 11;
const ICMP_EXC_TTL: u8 = 0;

/// Create a raw IP socket for sending custom TCP packets
/// 
/// This socket allows us to craft complete IP packets with custom headers,
/// including setting specific TTL values. Required for the 0trace technique.
pub fn create_raw_socket() -> Result<RawFd> {
    let fd = unsafe { socket(AF_INET, SOCK_RAW, IPPROTO_RAW) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).map_err(|e| anyhow!(e));
    }
    
    // Enable IP_HDRINCL so we can set our own IP header (including TTL)
    let one: c_int = 1;
    let rc = unsafe {
        setsockopt(
            fd,
            SOL_IP,
            IP_HDRINCL,
            &one as *const _ as *const c_void,
            std::mem::size_of::<c_int>() as u32,
        )
    };
    if rc != 0 {
        unsafe { close(fd) };
        return Err(std::io::Error::last_os_error()).map_err(|e| anyhow!(e));
    }
    
    eprintln!("[DEBUG create_raw_socket] Created raw socket fd={}", fd);
    Ok(fd)
}

/// Create a raw ICMP socket for receiving ICMP Time Exceeded messages
/// 
/// Unlike the raw IP socket used for sending, this socket receives ALL
/// ICMP packets arriving at the host. We filter for Time Exceeded messages
/// in userspace by parsing the ICMP payload.
/// 
/// This is the key difference from the MSG_ERRQUEUE approach - we create
/// a separate socket specifically for receiving ICMP, similar to how the
/// Go implementation uses pcap to capture ICMP packets.
pub fn create_icmp_socket() -> Result<RawFd> {
    let fd = unsafe { socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).map_err(|e| anyhow!(e));
    }
    
    eprintln!("[DEBUG create_icmp_socket] Created ICMP socket fd={}", fd);
    Ok(fd)
}

/// Send a TCP packet with custom TTL using raw socket
/// 
/// This crafts a complete IP + TCP packet mimicking an existing connection.
/// The packet has a specific TTL that will cause it to expire at a router,
/// triggering an ICMP Time Exceeded response.
/// 
/// Returns the IP ID of the sent packet for matching with ICMP responses.
pub fn send_tcp_probe(
    fd: RawFd,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ttl: u8,
) -> Result<u16> {
    eprintln!("[DEBUG send_tcp_probe] Sending TCP probe: {}:{} -> {}:{} TTL={}", 
        src_ip, src_port, dst_ip, dst_port, ttl);
    
    // Build IP header (20 bytes) + TCP header (20 bytes)
    let mut packet = [0u8; 40];
    
    // === IP Header ===
    packet[0] = 0x45; // Version (4) + IHL (5)
    packet[1] = 0x00; // DSCP + ECN
    let total_len = 40u16;
    packet[2..4].copy_from_slice(&total_len.to_be_bytes());
    
    // Generate IP ID based on current time
    let ip_id = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() & 0xFFFF) as u16;
    packet[4..6].copy_from_slice(&ip_id.to_be_bytes());
    
    packet[6] = 0x40; // Flags: Don't Fragment
    packet[7] = 0x00; // Fragment offset
    packet[8] = ttl;  // TTL - THE KEY VALUE!
    packet[9] = IPPROTO_TCP as u8; // Protocol: TCP
    // Checksum at [10..12] - calculated below
    packet[12..16].copy_from_slice(&u32::from(src_ip).to_be_bytes());
    packet[16..20].copy_from_slice(&u32::from(dst_ip).to_be_bytes());
    
    // Calculate IP checksum
    let mut sum: u32 = 0;
    for i in (0..20).step_by(2) {
        if i == 10 { continue; } // Skip checksum field
        sum += u16::from_be_bytes([packet[i], packet[i+1]]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    let ip_checksum = !(sum as u16);
    packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
    
    // === TCP Header ===
    packet[20..22].copy_from_slice(&src_port.to_be_bytes());
    packet[22..24].copy_from_slice(&dst_port.to_be_bytes());
    packet[24..28].copy_from_slice(&seq.to_be_bytes());
    packet[28..32].copy_from_slice(&0u32.to_be_bytes()); // ACK
    packet[32] = 0x50; // Data offset (5 * 4 = 20 bytes)
    packet[33] = 0x02; // Flags: SYN
    packet[34..36].copy_from_slice(&8192u16.to_be_bytes()); // Window
    // TCP checksum at [36..38] - calculated below
    packet[38..40].copy_from_slice(&0u16.to_be_bytes()); // Urgent pointer
    
    // Calculate TCP checksum with pseudo-header
    let mut sum: u32 = 0;
    // Pseudo-header
    sum += u16::from_be_bytes([packet[12], packet[13]]) as u32;
    sum += u16::from_be_bytes([packet[14], packet[15]]) as u32;
    sum += u16::from_be_bytes([packet[16], packet[17]]) as u32;
    sum += u16::from_be_bytes([packet[18], packet[19]]) as u32;
    sum += (IPPROTO_TCP as u16) as u32;
    sum += 20u32; // TCP length
    // TCP header
    for i in (20..40).step_by(2) {
        if i == 36 { continue; } // Skip checksum field
        sum += u16::from_be_bytes([packet[i], packet[i+1]]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    let tcp_checksum = !(sum as u16);
    packet[36..38].copy_from_slice(&tcp_checksum.to_be_bytes());
    
    // Send packet
    let dst_addr = sockaddr_in {
        sin_family: AF_INET as u16,
        sin_port: 0, // Ignored with IPPROTO_RAW
        sin_addr: libc::in_addr { s_addr: u32::from(dst_ip).to_be() },
        sin_zero: [0; 8],
    };
    
    let rc = unsafe {
        sendto(
            fd,
            packet.as_ptr() as *const c_void,
            packet.len(),
            0,
            &dst_addr as *const sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<sockaddr_in>() as u32,
        )
    };
    
    if rc < 0 {
        let e = std::io::Error::last_os_error();
        eprintln!("[DEBUG send_tcp_probe] sendto failed: {}", e);
        return Err(e).map_err(|e| anyhow!(e));
    }
    
    eprintln!("[DEBUG send_tcp_probe] Sent {} bytes, IP ID={}", rc, ip_id);
    Ok(ip_id)
}

/// Poll the ICMP socket for Time Exceeded messages
/// 
/// After sending a probe packet with low TTL, we wait for the router at that
/// hop to send back an ICMP Time Exceeded message. This function receives
/// ICMP packets from the raw ICMP socket and filters for Time Exceeded matching
/// our sent packet's IP ID.
/// 
/// This approach is similar to the Go implementation which uses pcap - we
/// capture ICMP packets and match them by IP ID in the embedded original packet.
/// 
/// Returns the router IP if a matching ICMP Time Exceeded is found, None if timeout.
pub async fn poll_icmp_socket(fd: RawFd, expected_ip_id: u16) -> Result<Option<String>> {
    // Receive ICMP packets using recvfrom. This is a blocking syscall;
    // call it inside spawn_blocking so we don't block the Tokio reactor.
    let res = tokio::task::spawn_blocking(move || {
        eprintln!("[DEBUG poll_icmp_socket] Starting, fd={}, expecting IP ID={}", fd, expected_ip_id);
        
        // Set a 2-second receive timeout
        let timeout_val = libc::timeval {
            tv_sec: 2,
            tv_usec: 0,
        };
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &timeout_val as *const _ as *const c_void,
                std::mem::size_of::<libc::timeval>() as u32,
            )
        };
        if rc < 0 {
            eprintln!("[DEBUG poll_icmp_socket] Failed to set SO_RCVTIMEO");
        } else {
            eprintln!("[DEBUG poll_icmp_socket] Socket timeout set to 2s");
        }
        
        // Buffer for receiving ICMP packet + IP header
        let mut buf = [0u8; 1500];
        let mut src_addr: sockaddr_in = unsafe { std::mem::zeroed() };
        let mut addr_len: libc::socklen_t = std::mem::size_of::<sockaddr_in>() as u32;
        
        // Try multiple times to receive ICMP packets
        // We may receive other ICMP packets (pings, etc.) before ours
        let max_attempts = 20;
        for attempt in 1..=max_attempts {
            eprintln!("[DEBUG poll_icmp_socket] Attempt {} of {}", attempt, max_attempts);
            
            let rc = unsafe {
                recvfrom(
                    fd,
                    buf.as_mut_ptr() as *mut c_void,
                    buf.len(),
                    0,
                    &mut src_addr as *mut _ as *mut libc::sockaddr,
                    &mut addr_len,
                )
            };
            
            if rc < 0 {
                let e = std::io::Error::last_os_error();
                if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut {
                    eprintln!("[DEBUG poll_icmp_socket] Timeout on attempt {}", attempt);
                    if attempt >= max_attempts {
                        eprintln!("[DEBUG poll_icmp_socket] No ICMP received after {} attempts", max_attempts);
                        return Ok(None);
                    }
                    continue;
                }
                eprintln!("[DEBUG poll_icmp_socket] recvfrom error: {}", e);
                return Err(e);
            }
            
            let bytes_read = rc as usize;
            eprintln!("[DEBUG poll_icmp_socket] Received {} bytes", bytes_read);
            
            // Parse IP header (first 20+ bytes)
            if bytes_read < 20 {
                eprintln!("[DEBUG poll_icmp_socket] Packet too small for IP header");
                continue;
            }
            
            let ip_header_len = ((buf[0] & 0x0F) * 4) as usize;
            if bytes_read < ip_header_len + 8 {
                eprintln!("[DEBUG poll_icmp_socket] Packet too small for ICMP header");
                continue;
            }
            
            // ICMP header starts after IP header
            let icmp_type = buf[ip_header_len];
            let icmp_code = buf[ip_header_len + 1];
            
            eprintln!("[DEBUG poll_icmp_socket] ICMP type={}, code={}", icmp_type, icmp_code);
            
            // Check if this is ICMP Time Exceeded (type 11, code 0)
            if icmp_type != ICMP_TIME_EXCEEDED || icmp_code != ICMP_EXC_TTL {
                eprintln!("[DEBUG poll_icmp_socket] Not a Time Exceeded message, skipping");
                continue;
            }
            
            // ICMP Time Exceeded contains the original IP header in its payload
            // Format: IP header (20) + ICMP header (8) + original IP header (20+) + original TCP header...
            let orig_ip_offset = ip_header_len + 8;
            if bytes_read < orig_ip_offset + 20 {
                eprintln!("[DEBUG poll_icmp_socket] No original IP header in ICMP payload");
                continue;
            }
            
            // Extract IP ID from the original packet's IP header (bytes 4-5)
            let orig_ip_id = u16::from_be_bytes([buf[orig_ip_offset + 4], buf[orig_ip_offset + 5]]);
            eprintln!("[DEBUG poll_icmp_socket] Original packet IP ID: {}, expected: {}", orig_ip_id, expected_ip_id);
            
            // Check if this ICMP is in response to our probe
            if orig_ip_id == expected_ip_id {
                let router_ip = std::net::Ipv4Addr::from(u32::from_be(src_addr.sin_addr.s_addr));
                eprintln!("[DEBUG poll_icmp_socket] Match! Router IP: {}", router_ip);
                return Ok(Some(router_ip.to_string()));
            } else {
                eprintln!("[DEBUG poll_icmp_socket] IP ID mismatch, continuing to listen...");
            }
        }
        
        eprintln!("[DEBUG poll_icmp_socket] No matching ICMP Time Exceeded received");
        Ok(None)
    })
    .await?;

    res.map_err(|e| anyhow!(e))
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_socket_operations_exist() {
        // Just verify the module compiles
    }
}
