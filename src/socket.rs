use anyhow::{anyhow, Result};
use std::os::fd::RawFd;
use std::net::Ipv4Addr;
use libc::{
    c_int, c_void, recvfrom, sendto, setsockopt,
    sockaddr_in, sockaddr_ll, socket, close, htons, bind, if_nametoindex, AF_INET, AF_PACKET, IPPROTO_RAW, IPPROTO_TCP, SOCK_RAW,
    IP_HDRINCL, SOL_IP, ETH_P_IP,
};
use crate::types::PacketModifications;

// ICMP constants
const ICMP_TIME_EXCEEDED: u8 = 11;
const ICMP_EXC_TTL: u8 = 0;

// Packet structure constants
const IP_HEADER_LEN: usize = 20;
const TCP_HEADER_LEN: usize = 20;
const ICMP_HEADER_LEN: usize = 8;
const ETHERNET_HEADER_LEN: usize = 14;
const PACKET_BUFFER_SIZE: usize = 1500;
const ICMP_EXTENSION_OFFSET: usize = 128;
const ICMP_EXTENSION_VERSION: u8 = 2;

// ICMP extension classes
const ICMP_EXT_CLASS_MPLS: u8 = 1;
const ICMP_EXT_TYPE_MPLS_STACK: u8 = 1;

/// MPLS label stack entry
#[derive(Debug, Clone)]
pub struct MplsLabel {
    pub label: u32,
    pub exp: u8,
    pub ttl: u8,
}

/// Hop information including router IP and optional MPLS labels
#[derive(Debug, Clone)]
pub struct HopInfo {
    pub router_ip: String,
    pub mpls_labels: Vec<MplsLabel>,
    pub modifications: PacketModifications,
}

/// Calculate IP header checksum
fn calculate_ip_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for i in (0..IP_HEADER_LEN).step_by(2) {
        if i == 10 { continue; } // Skip checksum field
        sum += u16::from_be_bytes([header[i], header[i+1]]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Calculate TCP checksum with pseudo-header
fn calculate_tcp_checksum(ip_header: &[u8], tcp_header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    
    // Pseudo-header: source IP, dest IP, protocol, TCP length
    sum += u16::from_be_bytes([ip_header[12], ip_header[13]]) as u32;
    sum += u16::from_be_bytes([ip_header[14], ip_header[15]]) as u32;
    sum += u16::from_be_bytes([ip_header[16], ip_header[17]]) as u32;
    sum += u16::from_be_bytes([ip_header[18], ip_header[19]]) as u32;
    sum += (IPPROTO_TCP as u16) as u32;
    sum += TCP_HEADER_LEN as u32;
    
    // TCP header
    for i in (0..TCP_HEADER_LEN).step_by(2) {
        if i == 16 { continue; } // Skip checksum field (offset 16 in TCP header)
        sum += u16::from_be_bytes([tcp_header[i], tcp_header[i+1]]) as u32;
    }
    
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Build IP header with specified parameters
fn build_ip_header(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    ttl: u8,
    total_length: u16,
) -> ([u8; IP_HEADER_LEN], u16) {
    let mut header = [0u8; IP_HEADER_LEN];
    
    header[0] = 0x45; // Version (4) + IHL (5)
    header[1] = 0x00; // DSCP + ECN
    header[2..4].copy_from_slice(&total_length.to_be_bytes());
    
    // Generate IP ID based on current time
    let ip_id = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() & 0xFFFF) as u16;
    header[4..6].copy_from_slice(&ip_id.to_be_bytes());
    
    header[6] = 0x40; // Flags: Don't Fragment
    header[7] = 0x00; // Fragment offset
    header[8] = ttl;
    header[9] = IPPROTO_TCP as u8;
    header[12..16].copy_from_slice(&u32::from(src_ip).to_be_bytes());
    header[16..20].copy_from_slice(&u32::from(dst_ip).to_be_bytes());
    
    let checksum = calculate_ip_checksum(&header);
    header[10..12].copy_from_slice(&checksum.to_be_bytes());
    
    (header, ip_id)
}

/// Build TCP header with specified parameters
fn build_tcp_header(
    src_port: u16,
    dst_port: u16,
    seq_num: u32,
) -> [u8; TCP_HEADER_LEN] {
    let mut header = [0u8; TCP_HEADER_LEN];
    
    header[0..2].copy_from_slice(&src_port.to_be_bytes());
    header[2..4].copy_from_slice(&dst_port.to_be_bytes());
    header[4..8].copy_from_slice(&seq_num.to_be_bytes());
    header[8..12].copy_from_slice(&0u32.to_be_bytes()); // ACK number
    header[12] = 0x50; // Data offset (5 * 4 = 20 bytes)
    header[13] = 0x02; // Flags: SYN
    header[14..16].copy_from_slice(&8192u16.to_be_bytes()); // Window size
    header[18..20].copy_from_slice(&0u16.to_be_bytes()); // Urgent pointer
    
    header
}

/// Create a raw IP socket for sending custom TCP packets
/// 
/// This socket allows us to craft complete IP packets with custom headers,
/// including setting specific TTL values. Required for the 0trace technique.
pub fn create_raw_socket() -> Result<RawFd> {
    let socket_fd = unsafe { socket(AF_INET, SOCK_RAW, IPPROTO_RAW) };
    if socket_fd < 0 {
        return Err(std::io::Error::last_os_error()).map_err(|e| anyhow!(e));
    }
    
    // Enable IP_HDRINCL so we can set our own IP header (including TTL)
    let enable_flag: c_int = 1;
    let result = unsafe {
        setsockopt(
            socket_fd,
            SOL_IP,
            IP_HDRINCL,
            &enable_flag as *const _ as *const c_void,
            std::mem::size_of::<c_int>() as u32,
        )
    };
    if result != 0 {
        unsafe { close(socket_fd) };
        return Err(std::io::Error::last_os_error()).map_err(|e| anyhow!(e));
    }
    
    eprintln!("[DEBUG create_raw_socket] Created raw socket fd={}", socket_fd);
    Ok(socket_fd)
}

/// Create a packet capture socket for receiving ICMP Time Exceeded messages
/// 
/// This creates an AF_PACKET socket which captures at the link layer,
/// similar to how the Go implementation uses pcap. This is necessary because
/// ICMP error messages (Time Exceeded) are not delivered to regular ICMP sockets -
/// they're handled specially by the kernel and delivered via IP_RECVERR or
/// visible only at the link layer.
/// 
/// AF_PACKET socket receives ALL IP packets, so we filter in userspace.
/// Bind socket to network interface
fn bind_to_interface(socket_fd: RawFd, interface_name: &str) {
    let ifname_cstr = format!("{}\0", interface_name);
    let interface_index = unsafe { if_nametoindex(ifname_cstr.as_ptr() as *const libc::c_char) };
    
    if interface_index == 0 {
        eprintln!("[DEBUG] Warning: Could not find {} interface, will receive from all", interface_name);
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
        eprintln!("[DEBUG] Warning: Failed to bind to {}: {}", interface_name, error);
    } else {
        eprintln!("[DEBUG] Bound to {} (ifindex={})", interface_name, interface_index);
    }
}

/// Set socket receive buffer size
fn set_receive_buffer_size(socket_fd: RawFd, size_bytes: c_int) {
    let result = unsafe {
        setsockopt(
            socket_fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &size_bytes as *const _ as *const c_void,
            std::mem::size_of::<c_int>() as u32,
        )
    };
    
    if result < 0 {
        eprintln!("[DEBUG] Warning: Failed to set SO_RCVBUF");
    }
}

pub fn create_icmp_socket(_bind_addr: Option<Ipv4Addr>) -> Result<RawFd> {
    // Create AF_PACKET socket to capture all IP packets at link layer
    // This is like using pcap but with raw sockets
    let socket_fd = unsafe { socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP as u16) as i32) };
    if socket_fd < 0 {
        return Err(std::io::Error::last_os_error()).map_err(|e| anyhow!(e));
    }
    
    // Bind to eth0 interface (the main network interface in the container)
    bind_to_interface(socket_fd, "eth0");
    
    // Set receive buffer size to ensure we don't miss packets (256KB)
    set_receive_buffer_size(socket_fd, 256 * 1024);
    
    eprintln!("[DEBUG create_icmp_socket] Created AF_PACKET socket fd={} (link-layer capture)", socket_fd);
    Ok(socket_fd)
}

/// Send a TCP packet with custom TTL using raw socket
/// 
/// This crafts a complete IP + TCP packet mimicking an existing connection.
/// The packet has a specific TTL that will cause it to expire at a router,
/// triggering an ICMP Time Exceeded response.
/// 
/// Returns the IP ID of the sent packet for matching with ICMP responses.
pub fn send_tcp_probe(
    socket_fd: RawFd,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq_num: u32,
    ttl: u8,
) -> Result<u16> {
    eprintln!("[DEBUG send_tcp_probe] Sending TCP probe: {}:{} -> {}:{} TTL={}", 
        src_ip, src_port, dst_ip, dst_port, ttl);
    
    const TOTAL_PACKET_LEN: u16 = (IP_HEADER_LEN + TCP_HEADER_LEN) as u16;
    let mut packet = [0u8; TOTAL_PACKET_LEN as usize];
    
    // Build IP header
    let (ip_header, packet_id) = build_ip_header(src_ip, dst_ip, ttl, TOTAL_PACKET_LEN);
    packet[..IP_HEADER_LEN].copy_from_slice(&ip_header);
    
    // Build TCP header
    let mut tcp_header = build_tcp_header(src_port, dst_port, seq_num);
    
    // Calculate TCP checksum
    let tcp_checksum = calculate_tcp_checksum(&ip_header, &tcp_header);
    tcp_header[16..18].copy_from_slice(&tcp_checksum.to_be_bytes());
    
    packet[IP_HEADER_LEN..].copy_from_slice(&tcp_header);
    
    // Send packet
    let dest_addr = sockaddr_in {
        sin_family: AF_INET as u16,
        sin_port: 0, // Ignored with IPPROTO_RAW
        sin_addr: libc::in_addr { s_addr: u32::from(dst_ip).to_be() },
        sin_zero: [0; 8],
    };
    
    let bytes_sent = unsafe {
        sendto(
            socket_fd,
            packet.as_ptr() as *const c_void,
            packet.len(),
            0,
            &dest_addr as *const sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<sockaddr_in>() as u32,
        )
    };
    
    if bytes_sent < 0 {
        let error = std::io::Error::last_os_error();
        eprintln!("[DEBUG send_tcp_probe] sendto failed: {}", error);
        return Err(error).map_err(|e| anyhow!(e));
    }
    
    eprintln!("[DEBUG send_tcp_probe] Sent {} bytes, IP ID={}", bytes_sent, packet_id);
    Ok(packet_id)
}

/// Extract IP addresses from IP header
fn extract_ip_addresses(buffer: &[u8], ip_offset: usize) -> (Ipv4Addr, Ipv4Addr) {
    let src_ip = Ipv4Addr::new(
        buffer[ip_offset + 12],
        buffer[ip_offset + 13],
        buffer[ip_offset + 14],
        buffer[ip_offset + 15],
    );
    let dst_ip = Ipv4Addr::new(
        buffer[ip_offset + 16],
        buffer[ip_offset + 17],
        buffer[ip_offset + 18],
        buffer[ip_offset + 19],
    );
    (src_ip, dst_ip)
}

/// Parse MPLS label from 4-byte word
fn parse_mpls_label(label_word: u32) -> (MplsLabel, bool) {
    let label = (label_word >> 12) & 0xFFFFF;
    let exp = ((label_word >> 9) & 0x7) as u8;
    let is_bottom_of_stack = ((label_word >> 8) & 0x1) == 1;
    let ttl = (label_word & 0xFF) as u8;
    
    let mpls_label = MplsLabel { label, exp, ttl };
    (mpls_label, is_bottom_of_stack)
}

/// Parse MPLS extensions from ICMP packet (RFC 4884, RFC 4950)
fn parse_mpls_extensions(buffer: &[u8], icmp_offset: usize, packet_size: usize) -> Vec<MplsLabel> {
    let mut mpls_labels = Vec::new();
    let extension_offset = icmp_offset + ICMP_EXTENSION_OFFSET;
    
    if packet_size <= extension_offset + 4 {
        eprintln!("[DEBUG] Packet too small for extensions (size={}, need > {})", 
            packet_size, extension_offset + 4);
        return mpls_labels;
    }
    
    let ext_version = (buffer[extension_offset] >> 4) & 0x0F;
    let ext_checksum = u16::from_be_bytes([
        buffer[extension_offset + 2],
        buffer[extension_offset + 3]
    ]);
    
    eprintln!("[DEBUG] Extension header at offset {}: version={}, checksum=0x{:04x}", 
        extension_offset, ext_version, ext_checksum);
    
    if ext_version != ICMP_EXTENSION_VERSION {
        eprintln!("[DEBUG] No ICMP extensions (version={}, expected {})", 
            ext_version, ICMP_EXTENSION_VERSION);
        return mpls_labels;
    }
    
    eprintln!("[DEBUG] ICMP extensions present (version {})", ICMP_EXTENSION_VERSION);
    
    let mut obj_offset = extension_offset + 4;
    while obj_offset + 4 <= packet_size {
        let obj_len = u16::from_be_bytes([
            buffer[obj_offset],
            buffer[obj_offset + 1]
        ]) as usize;
        let class_num = buffer[obj_offset + 2];
        let c_type = buffer[obj_offset + 3];
        
        eprintln!("[DEBUG] Extension object: len={}, class={}, type={}", 
            obj_len, class_num, c_type);
        
        if obj_len < 4 || obj_offset + obj_len > packet_size {
            break;
        }
        
        // Class 1, Type 1 = MPLS Stack Entry
        if class_num == ICMP_EXT_CLASS_MPLS && c_type == ICMP_EXT_TYPE_MPLS_STACK {
            eprintln!("[DEBUG] MPLS Stack Entry found");
            let mut label_offset = obj_offset + 4;
            
            while label_offset + 4 <= obj_offset + obj_len {
                let label_word = u32::from_be_bytes([
                    buffer[label_offset],
                    buffer[label_offset + 1],
                    buffer[label_offset + 2],
                    buffer[label_offset + 3]
                ]);
                
                let (mpls_label, is_bottom) = parse_mpls_label(label_word);
                eprintln!("[DEBUG] MPLS Label: {}, EXP: {}, S: {}, TTL: {}", 
                    mpls_label.label, mpls_label.exp, is_bottom as u8, mpls_label.ttl);
                
                mpls_labels.push(mpls_label);
                label_offset += 4;
                
                if is_bottom {
                    break;
                }
            }
        }
        
        obj_offset += obj_len;
    }
    
    mpls_labels
}

/// Check if received packet is ICMP Time Exceeded for our probe
/// Poll the ICMP socket for Time Exceeded messages matching ANY of the expected IP IDs
/// 
/// This is the key function for 0trace - we receive any ICMP Time Exceeded message
/// and check if it matches any of our probe packets.
/// 
/// Returns (IP ID, router IP, MPLS labels, modifications) if a matching ICMP is found, None if timeout.
pub async fn poll_icmp_any(
    socket_fd: RawFd,
    expected_ip_ids: &std::collections::HashMap<u16, u8>,
    timeout_ms: u64
) -> Result<Option<(u16, HopInfo)>> {
    let expected_map = expected_ip_ids.clone();
    
    let result = tokio::task::spawn_blocking(move || {
        eprintln!("[DEBUG poll_icmp_any] Waiting for ICMP matching any of {} IP IDs", expected_map.len());
        
        // Set receive timeout - convert milliseconds to seconds and microseconds
        let timeout_seconds = (timeout_ms / 1000) as i64;
        let timeout_microseconds = ((timeout_ms % 1000) * 1000) as i64;
        set_receive_timeout(socket_fd, timeout_seconds, timeout_microseconds);
        
        let mut receive_buffer = [0u8; PACKET_BUFFER_SIZE];
        let mut src_addr: sockaddr_in = unsafe { std::mem::zeroed() };
        let mut addr_len: libc::socklen_t = std::mem::size_of::<sockaddr_in>() as u32;
        
        // Build set of IP IDs for quick checking
        let expected_ids: std::collections::HashSet<u16> = expected_map.keys().copied().collect();
        
        // Try to receive ICMP packets and check if any match our expected IP IDs
        const MAX_RECEIVE_ATTEMPTS: u32 = 50;
        for _attempt in 1..=MAX_RECEIVE_ATTEMPTS {
            let bytes_received = unsafe {
                recvfrom(
                    socket_fd,
                    receive_buffer.as_mut_ptr() as *mut c_void,
                    receive_buffer.len(),
                    0,
                    &mut src_addr as *mut _ as *mut libc::sockaddr,
                    &mut addr_len,
                )
            };
            
            if bytes_received < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::WouldBlock || error.kind() == std::io::ErrorKind::TimedOut {
                    return Ok(None);
                }
                return Err(error);
            }
            
            let packet_size = bytes_received as usize;
            
            // Try to parse as ICMP Time Exceeded and check if IP ID matches any expected
            if let Some(matched_id) = check_icmp_for_any_id(&receive_buffer, packet_size, &expected_ids) {
                // Get the TTL for this probe
                if let Some(&sent_ttl) = expected_map.get(&matched_id) {
                    eprintln!("[DEBUG poll_icmp_any] Found match for IP ID {} (TTL={})", matched_id, sent_ttl);
                    
                    // Re-parse to get full hop info with modifications analysis
                    if let Some((router_ip, mpls_labels, modifications)) = 
                        parse_icmp_time_exceeded(&receive_buffer, packet_size, matched_id, sent_ttl) {
                        return Ok(Some((matched_id, HopInfo {
                            router_ip: router_ip.to_string(),
                            mpls_labels,
                            modifications,
                        })));
                    }
                }
            }
        }
        
        Ok(None)
    })
    .await?;

    result.map_err(|e| anyhow!(e))
}

/// Check if an ICMP packet matches any of the expected IP IDs
fn check_icmp_for_any_id(buffer: &[u8], packet_size: usize, expected_ids: &std::collections::HashSet<u16>) -> Option<u16> {
    if packet_size < ETHERNET_HEADER_LEN + IP_HEADER_LEN {
        return None;
    }
    
    let ethertype = u16::from_be_bytes([buffer[12], buffer[13]]);
    if ethertype != 0x0800 {
        return None;
    }
    
    let ip_offset = ETHERNET_HEADER_LEN;
    let ip_protocol = buffer[ip_offset + 9];
    
    if ip_protocol != 1 {  // Not ICMP
        return None;
    }
    
    let ip_header_len = ((buffer[ip_offset] & 0x0F) * 4) as usize;
    if packet_size < ip_offset + ip_header_len + ICMP_HEADER_LEN {
        return None;
    }
    
    let icmp_offset = ip_offset + ip_header_len;
    let icmp_type = buffer[icmp_offset];
    let icmp_code = buffer[icmp_offset + 1];
    
    if icmp_type != ICMP_TIME_EXCEEDED || icmp_code != ICMP_EXC_TTL {
        return None;
    }
    
    let orig_ip_offset = icmp_offset + ICMP_HEADER_LEN;
    if packet_size < orig_ip_offset + IP_HEADER_LEN {
        return None;
    }
    
    let orig_ip_id = u16::from_be_bytes([
        buffer[orig_ip_offset + 4],
        buffer[orig_ip_offset + 5]
    ]);
    
    if expected_ids.contains(&orig_ip_id) {
        Some(orig_ip_id)
    } else {
        None
    }
}

/// Analyze packet modifications by comparing original sent packet with what's in ICMP
fn analyze_packet_modifications(
    buffer: &[u8],
    packet_size: usize,
    icmp_offset: usize,
    expected_ttl: u8,
) -> PacketModifications {
    let mut mods = PacketModifications::default();
    let mut modifications = Vec::new();
    
    // Original IP header is in ICMP payload after ICMP header (8 bytes)
    let orig_ip_offset = icmp_offset + ICMP_HEADER_LEN;
    
    if packet_size < orig_ip_offset + IP_HEADER_LEN {
        return mods;
    }
    
    // Check IP flags (byte 6-7)
    let orig_flags = buffer[orig_ip_offset + 6];
    let df_flag = (orig_flags & 0x40) != 0; // Don't Fragment
    let mf_flag = (orig_flags & 0x20) != 0; // More Fragments
    
    // We sent DF=1, MF=0
    if !df_flag {
        mods.flags_modified = true;
        modifications.push("DF flag cleared".to_string());
    }
    if mf_flag {
        mods.flags_modified = true;
        modifications.push("MF flag set".to_string());
    }
    
    // Check TTL (byte 8) - embedded packet should have TTL=1 when it reached the router
    // (original sent TTL was expected_ttl, router decremented it to 0 and sent ICMP)
    let orig_ttl = buffer[orig_ip_offset + 8];
    
    // The TTL in ICMP-embedded packet should be 1 (what router saw before decrementing)
    // Some routers might show 0 (after decrement), some show 1 (before)
    if orig_ttl > 1 {
        mods.ttl_modified = true;
        modifications.push(format!("Embedded TTL={} (expected 0 or 1, sent {})", orig_ttl, expected_ttl));
    }
    
    // Check IP header length - if > 5, there were IP options
    let orig_ihl = buffer[orig_ip_offset] & 0x0F;
    if orig_ihl > 5 {
        // We didn't send options, but they appear in response
        modifications.push(format!("IP options added (IHL={})", orig_ihl));
    }
    
    // Check if we have TCP header in ICMP payload
    if packet_size >= orig_ip_offset + IP_HEADER_LEN + 14 { // At least TCP flags
        let tcp_offset = orig_ip_offset + IP_HEADER_LEN;
        let tcp_flags = buffer[tcp_offset + 13];
        let syn_flag = (tcp_flags & 0x02) != 0;
        
        // We sent SYN
        if !syn_flag {
            mods.tcp_flags_modified = true;
            modifications.push("SYN flag cleared".to_string());
        }
    }
    
    mods.modifications = modifications;
    mods
}

/// Parse ICMP Time Exceeded packet to extract router IP, MPLS labels, and modifications
fn parse_icmp_time_exceeded(
    buffer: &[u8],
    packet_size: usize,
    _expected_ip_id: u16,
    sent_ttl: u8,
) -> Option<(Ipv4Addr, Vec<MplsLabel>, PacketModifications)> {
    if packet_size < ETHERNET_HEADER_LEN + IP_HEADER_LEN {
        return None;
    }
    
    let ip_offset = ETHERNET_HEADER_LEN;
    let ip_header_len = ((buffer[ip_offset] & 0x0F) * 4) as usize;
    
    let (router_ip, _) = extract_ip_addresses(buffer, ip_offset);
    
    let icmp_offset = ip_offset + ip_header_len;
    let mpls_labels = parse_mpls_extensions(buffer, icmp_offset, packet_size);
    
    // Analyze modifications
    let modifications = analyze_packet_modifications(buffer, packet_size, icmp_offset, sent_ttl);
    
    Some((router_ip, mpls_labels, modifications))
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
/// Set socket receive timeout
fn set_receive_timeout(socket_fd: RawFd, timeout_seconds: i64, timeout_microseconds: i64) {
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
        eprintln!("[DEBUG] Failed to set SO_RCVTIMEO");
    } else {
        eprintln!("[DEBUG] Socket timeout set to {}.{:06}s", timeout_seconds, timeout_microseconds);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_socket_operations_exist() {
        // Just verify the module compiles
    }
}
