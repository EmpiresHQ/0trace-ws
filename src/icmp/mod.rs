//! ICMP packet parsing and analysis

use std::net::Ipv4Addr;
use crate::constants::*;
use crate::types::PacketModifications;

/// MPLS label stack entry
#[derive(Debug, Clone)]
pub struct MplsLabel {
    pub label: u32,
    pub experimental_bits: u8,
    pub ttl: u8,
}

/// Information about a network hop including router IP and optional MPLS labels
#[derive(Debug, Clone)]
pub struct HopInfo {
    pub router_ip: String,
    pub mpls_labels: Vec<MplsLabel>,
    pub modifications: PacketModifications,
}

/// Check if a packet buffer contains ICMP Time Exceeded matching any expected IP ID
pub fn check_icmp_for_any_id(
    buffer: &[u8],
    packet_size: usize,
    expected_ids: &std::collections::HashSet<u16>,
) -> Option<u16> {
    // Need at least Ethernet + IP header
    if packet_size < ETHERNET_HEADER_LEN + IP_HEADER_LEN {
        return None;
    }
    
    // Check Ethernet type (IPv4)
    let ethertype = u16::from_be_bytes([buffer[12], buffer[13]]);
    if ethertype != ETHERTYPE_IPV4 {
        return None;
    }
    
    let ip_offset = ETHERNET_HEADER_LEN;
    let ip_protocol = buffer[ip_offset + 9];
    
    // Must be ICMP protocol
    if ip_protocol != IPPROTO_ICMP {
        return None;
    }
    
    let ip_header_len = ((buffer[ip_offset] & 0x0F) * 4) as usize;
    if packet_size < ip_offset + ip_header_len + ICMP_HEADER_LEN {
        return None;
    }
    
    let icmp_offset = ip_offset + ip_header_len;
    let icmp_type = buffer[icmp_offset];
    let icmp_code = buffer[icmp_offset + 1];
    
    // Must be Time Exceeded with TTL expired code
    if icmp_type != ICMP_TIME_EXCEEDED || icmp_code != ICMP_TIME_EXCEEDED_CODE {
        return None;
    }
    
    // Extract IP ID from original packet embedded in ICMP
    let original_ip_offset = icmp_offset + ICMP_HEADER_LEN;
    if packet_size < original_ip_offset + IP_HEADER_LEN {
        return None;
    }
    
    let original_ip_id = u16::from_be_bytes([
        buffer[original_ip_offset + 4],
        buffer[original_ip_offset + 5],
    ]);
    
    // Check if this IP ID matches any we're expecting
    if expected_ids.contains(&original_ip_id) {
        Some(original_ip_id)
    } else {
        None
    }
}

/// Parse complete ICMP Time Exceeded packet to extract hop information
pub fn parse_icmp_time_exceeded(
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
    
    // Extract router IP (source of ICMP packet)
    let router_ip = extract_router_ip(buffer, ip_offset);
    
    let icmp_offset = ip_offset + ip_header_len;
    
    // Parse MPLS extensions if present
    let mpls_labels = parse_mpls_extensions(buffer, icmp_offset, packet_size);
    
    // Analyze packet modifications
    let modifications = analyze_packet_modifications(buffer, packet_size, icmp_offset, sent_ttl);
    
    Some((router_ip, mpls_labels, modifications))
}

/// Extract router IP address from ICMP packet
fn extract_router_ip(buffer: &[u8], ip_offset: usize) -> Ipv4Addr {
    Ipv4Addr::new(
        buffer[ip_offset + 12],
        buffer[ip_offset + 13],
        buffer[ip_offset + 14],
        buffer[ip_offset + 15],
    )
}

/// Parse MPLS label stack from ICMP extensions (RFC 4884, RFC 4950)
fn parse_mpls_extensions(buffer: &[u8], icmp_offset: usize, packet_size: usize) -> Vec<MplsLabel> {
    let mut mpls_labels = Vec::new();
    let extension_offset = icmp_offset + ICMP_EXTENSION_OFFSET;
    
    // Check if packet is large enough for extensions
    if packet_size <= extension_offset + 4 {
        return mpls_labels;
    }
    
    let ext_version = (buffer[extension_offset] >> 4) & 0x0F;
    
    // Must have correct ICMP extension version
    if ext_version != ICMP_EXTENSION_VERSION {
        return mpls_labels;
    }
    
    eprintln!("[DEBUG ICMP] Found ICMP extensions (version {})", ICMP_EXTENSION_VERSION);
    
    // Parse extension objects
    let mut object_offset = extension_offset + 4;
    while object_offset + 4 <= packet_size {
        let object_length = u16::from_be_bytes([
            buffer[object_offset],
            buffer[object_offset + 1],
        ]) as usize;
        
        let class_num = buffer[object_offset + 2];
        let c_type = buffer[object_offset + 3];
        
        // Validate object length
        if object_length < 4 || object_offset + object_length > packet_size {
            break;
        }
        
        // Parse MPLS Stack Entry (Class 1, Type 1)
        if class_num == ICMP_EXT_CLASS_MPLS && c_type == ICMP_EXT_TYPE_MPLS_STACK {
            mpls_labels.extend(parse_mpls_stack(&buffer[object_offset + 4..object_offset + object_length]));
        }
        
        object_offset += object_length;
    }
    
    mpls_labels
}

/// Parse MPLS label stack from extension object data
fn parse_mpls_stack(data: &[u8]) -> Vec<MplsLabel> {
    let mut labels = Vec::new();
    let mut offset = 0;
    
    while offset + MPLS_LABEL_SIZE <= data.len() {
        let label_word = u32::from_be_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        
        let (mpls_label, is_bottom_of_stack) = parse_mpls_label(label_word);
        
        eprintln!("[DEBUG ICMP] MPLS Label: {}, EXP: {}, TTL: {}, Bottom: {}", 
            mpls_label.label, mpls_label.experimental_bits, mpls_label.ttl, is_bottom_of_stack);
        
        labels.push(mpls_label);
        offset += MPLS_LABEL_SIZE;
        
        if is_bottom_of_stack {
            break;
        }
    }
    
    labels
}

/// Parse a single MPLS label from 4-byte word
fn parse_mpls_label(label_word: u32) -> (MplsLabel, bool) {
    let label = (label_word >> 12) & 0xFFFFF;  // 20 bits
    let exp = ((label_word >> 9) & 0x7) as u8;  // 3 bits
    let is_bottom = ((label_word >> 8) & 0x1) == 1;  // 1 bit (S bit)
    let ttl = (label_word & 0xFF) as u8;  // 8 bits
    
    let mpls_label = MplsLabel {
        label,
        experimental_bits: exp,
        ttl,
    };
    
    (mpls_label, is_bottom)
}

/// Analyze packet modifications by comparing original sent packet with embedded packet in ICMP
fn analyze_packet_modifications(
    buffer: &[u8],
    packet_size: usize,
    icmp_offset: usize,
    expected_ttl: u8,
) -> PacketModifications {
    let mut modifications = PacketModifications::default();
    let mut modification_descriptions = Vec::new();
    
    // Original packet is embedded in ICMP payload after 8-byte ICMP header
    let original_ip_offset = icmp_offset + ICMP_HEADER_LEN;
    
    if packet_size < original_ip_offset + IP_HEADER_LEN {
        return modifications;
    }
    
    // Check IP flags (Don't Fragment, More Fragments)
    let original_flags = buffer[original_ip_offset + 6];
    let dont_fragment = (original_flags & IP_FLAG_DONT_FRAGMENT) != 0;
    let more_fragments = (original_flags & IP_FLAG_MORE_FRAGMENTS) != 0;
    
    // We sent DF=1, MF=0
    if !dont_fragment {
        modifications.flags_modified = true;
        modification_descriptions.push("DF flag cleared".to_string());
    }
    if more_fragments {
        modifications.flags_modified = true;
        modification_descriptions.push("MF flag set".to_string());
    }
    
    // Check TTL - embedded packet shows what router saw before decrementing
    let embedded_ttl = buffer[original_ip_offset + 8];
    
    // Expected: TTL should be 1 (router saw it before decrementing to 0)
    // Some routers show 0 (after decrement), some show 1 (before)
    if embedded_ttl > 1 {
        modifications.ttl_modified = true;
        modification_descriptions.push(format!(
            "Embedded TTL={} (expected 0 or 1, originally sent {})",
            embedded_ttl, expected_ttl
        ));
    }
    
    // Check IP options - we don't send any, so IHL should be 5
    let ip_header_length = buffer[original_ip_offset] & 0x0F;
    if ip_header_length > 5 {
        modification_descriptions.push(format!("IP options added (IHL={})", ip_header_length));
    }
    
    // Check TCP flags if TCP header is present
    if packet_size >= original_ip_offset + IP_HEADER_LEN + 14 {
        let tcp_offset = original_ip_offset + IP_HEADER_LEN;
        let tcp_flags = buffer[tcp_offset + 13];
        let has_syn = (tcp_flags & TCP_FLAG_SYN) != 0;
        
        // We sent SYN flag
        if !has_syn {
            modifications.tcp_flags_modified = true;
            modification_descriptions.push("SYN flag cleared".to_string());
        }
    }
    
    modifications.modifications = modification_descriptions;
    modifications
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mpls_label_parsing() {
        // Label=100, EXP=5, S=1, TTL=64
        let label_word: u32 = (100 << 12) | (5 << 9) | (1 << 8) | 64;
        let (label, is_bottom) = parse_mpls_label(label_word);
        
        assert_eq!(label.label, 100);
        assert_eq!(label.experimental_bits, 5);
        assert_eq!(label.ttl, 64);
        assert!(is_bottom);
    }
}
