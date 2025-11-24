/// Network protocol and packet constants

// ICMP protocol constants
pub const ICMP_TIME_EXCEEDED: u8 = 11;
pub const ICMP_TIME_EXCEEDED_CODE: u8 = 0;

// ICMP extension format (RFC 4884, RFC 4950)
pub const ICMP_EXTENSION_OFFSET: usize = 128;
pub const ICMP_EXTENSION_VERSION: u8 = 2;
pub const ICMP_EXT_CLASS_MPLS: u8 = 1;
pub const ICMP_EXT_TYPE_MPLS_STACK: u8 = 1;

// Packet structure sizes
pub const IP_HEADER_LEN: usize = 20;
pub const TCP_HEADER_LEN: usize = 20;
pub const ICMP_HEADER_LEN: usize = 8;
pub const ETHERNET_HEADER_LEN: usize = 14;
pub const PACKET_BUFFER_SIZE: usize = 1500;
pub const MPLS_LABEL_SIZE: usize = 4;

// IP protocol numbers
pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_TCP: u8 = 6;

// Ethernet types
pub const ETHERTYPE_IPV4: u16 = 0x0800;

// TCP flags
pub const TCP_FLAG_SYN: u8 = 0x02;

// IP flags
pub const IP_FLAG_DONT_FRAGMENT: u8 = 0x40;
pub const IP_FLAG_MORE_FRAGMENTS: u8 = 0x20;

// Default configuration
pub const DEFAULT_MAX_HOPS: u32 = 30;
pub const DEFAULT_PER_TTL_TIMEOUT_MS: u32 = 1200;
pub const DEFAULT_BIND_HOST: &str = "0.0.0.0";
pub const DEFAULT_SOCKET_RECV_BUFFER_SIZE: i32 = 256 * 1024; // 256KB
pub const DEFAULT_INTERFACE_NAME: &str = "eth0";

// Probe timing
pub const PROBE_SEND_DELAY_MICROS: u64 = 100;
pub const MAX_ICMP_RECEIVE_ATTEMPTS: u32 = 50;
pub const COLLECTION_TIMEOUT_MULTIPLIER: u32 = 3;

// Default TCP values
pub const DEFAULT_TCP_WINDOW_SIZE: u16 = 8192;
