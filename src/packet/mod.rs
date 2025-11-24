/// Packet building and checksum calculation utilities

use std::net::Ipv4Addr;
use crate::constants::*;

/// Build an IP header with the specified parameters
/// Returns the header bytes and the generated IP ID
pub fn build_ip_header(
    source_ip: Ipv4Addr,
    dest_ip: Ipv4Addr,
    ttl: u8,
    total_length: u16,
) -> ([u8; IP_HEADER_LEN], u16) {
    let mut header = [0u8; IP_HEADER_LEN];
    
    // Version (4) + IHL (5) = 0x45
    header[0] = 0x45;
    // DSCP + ECN
    header[1] = 0x00;
    // Total length
    header[2..4].copy_from_slice(&total_length.to_be_bytes());
    
    // Generate unique IP ID based on current time
    let ip_id = generate_ip_id();
    header[4..6].copy_from_slice(&ip_id.to_be_bytes());
    
    // Flags: Don't Fragment
    header[6] = IP_FLAG_DONT_FRAGMENT;
    // Fragment offset
    header[7] = 0x00;
    // TTL
    header[8] = ttl;
    // Protocol (TCP)
    header[9] = IPPROTO_TCP;
    // Checksum (will be filled below)
    header[10] = 0;
    header[11] = 0;
    // Source IP
    header[12..16].copy_from_slice(&u32::from(source_ip).to_be_bytes());
    // Destination IP
    header[16..20].copy_from_slice(&u32::from(dest_ip).to_be_bytes());
    
    // Calculate and insert checksum
    let checksum = calculate_ip_checksum(&header);
    header[10..12].copy_from_slice(&checksum.to_be_bytes());
    
    (header, ip_id)
}

/// Build a TCP header with the specified parameters
pub fn build_tcp_header(
    source_port: u16,
    dest_port: u16,
    sequence_number: u32,
) -> [u8; TCP_HEADER_LEN] {
    let mut header = [0u8; TCP_HEADER_LEN];
    
    // Source port
    header[0..2].copy_from_slice(&source_port.to_be_bytes());
    // Destination port
    header[2..4].copy_from_slice(&dest_port.to_be_bytes());
    // Sequence number
    header[4..8].copy_from_slice(&sequence_number.to_be_bytes());
    // ACK number (0 for SYN)
    header[8..12].copy_from_slice(&0u32.to_be_bytes());
    // Data offset (5 * 4 = 20 bytes) << 4
    header[12] = 0x50;
    // Flags: SYN
    header[13] = TCP_FLAG_SYN;
    // Window size
    header[14..16].copy_from_slice(&DEFAULT_TCP_WINDOW_SIZE.to_be_bytes());
    // Checksum (will be filled by caller)
    header[16] = 0;
    header[17] = 0;
    // Urgent pointer
    header[18..20].copy_from_slice(&0u16.to_be_bytes());
    
    header
}

/// Calculate IP header checksum
pub fn calculate_ip_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    
    // Sum all 16-bit words, skipping checksum field at offset 10-11
    for i in (0..IP_HEADER_LEN).step_by(2) {
        if i == 10 {
            continue; // Skip checksum field
        }
        let word = u16::from_be_bytes([header[i], header[i + 1]]);
        sum += word as u32;
    }
    
    // Fold 32-bit sum to 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    // One's complement
    !(sum as u16)
}

/// Calculate TCP checksum with pseudo-header
pub fn calculate_tcp_checksum(ip_header: &[u8], tcp_header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    
    // Pseudo-header: source IP (2 words)
    sum += u16::from_be_bytes([ip_header[12], ip_header[13]]) as u32;
    sum += u16::from_be_bytes([ip_header[14], ip_header[15]]) as u32;
    // Pseudo-header: destination IP (2 words)
    sum += u16::from_be_bytes([ip_header[16], ip_header[17]]) as u32;
    sum += u16::from_be_bytes([ip_header[18], ip_header[19]]) as u32;
    // Pseudo-header: protocol (TCP)
    sum += IPPROTO_TCP as u32;
    // Pseudo-header: TCP length
    sum += TCP_HEADER_LEN as u32;
    
    // TCP header
    for i in (0..TCP_HEADER_LEN).step_by(2) {
        if i == 16 {
            continue; // Skip checksum field
        }
        let word = u16::from_be_bytes([tcp_header[i], tcp_header[i + 1]]);
        sum += word as u32;
    }
    
    // Fold 32-bit sum to 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    // One's complement
    !(sum as u16)
}

/// Generate unique IP ID based on current time
fn generate_ip_id() -> u16 {
    (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() & 0xFFFF) as u16
}

/// Generate TCP sequence number based on current time
pub fn generate_sequence_number(base_offset: u32) -> u32 {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    
    timestamp.wrapping_add(base_offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_header_building() {
        let src = Ipv4Addr::new(192, 168, 1, 1);
        let dst = Ipv4Addr::new(8, 8, 8, 8);
        let (header, ip_id) = build_ip_header(src, dst, 64, 40);
        
        assert_eq!(header[0], 0x45); // Version + IHL
        assert_eq!(header[8], 64);   // TTL
        assert_eq!(header[9], IPPROTO_TCP); // Protocol
        assert!(ip_id > 0);
    }

    #[test]
    fn test_tcp_header_building() {
        let header = build_tcp_header(12345, 80, 1000);
        
        assert_eq!(u16::from_be_bytes([header[0], header[1]]), 12345); // Source port
        assert_eq!(u16::from_be_bytes([header[2], header[3]]), 80);    // Dest port
        assert_eq!(header[13], TCP_FLAG_SYN); // Flags
    }

    #[test]
    fn test_checksum_calculation() {
        let mut header = [0u8; IP_HEADER_LEN];
        header[0] = 0x45;
        header[8] = 64;
        
        let checksum = calculate_ip_checksum(&header);
        assert!(checksum > 0);
    }
}
