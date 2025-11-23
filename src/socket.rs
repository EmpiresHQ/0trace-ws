use anyhow::{anyhow, Result};
use std::os::fd::RawFd;
use std::net::Ipv4Addr;
use libc::{
    c_int, c_void, cmsghdr, iovec, msghdr, recvmsg, sendto, setsockopt, sock_extended_err, 
    sockaddr_in, socket, close, AF_INET, IPPROTO_RAW, IPPROTO_TCP, SOCK_RAW,
    IP_RECVERR, IP_TTL, IP_HDRINCL, MSG_ERRQUEUE, SOL_IP,
};

// ICMP constants
const ICMP_TIME_EXCEEDED: u8 = 11;
const ICMP_EXC_TTL: u8 = 0;
const SO_EE_ORIGIN_ICMP: u8 = 2;

/// Create a raw IP socket for sending custom TCP packets
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

/// Send a TCP packet with custom TTL using raw socket
/// This crafts a minimal TCP packet to trigger ICMP Time Exceeded responses
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
    let mut packet = vec![0u8; 40];
    
    // IP Header
    packet[0] = 0x45; // Version (4) + IHL (5)
    packet[1] = 0x00; // DSCP + ECN
    let total_len = 40u16;
    packet[2..4].copy_from_slice(&total_len.to_be_bytes());
    
    let ip_id = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() & 0xFFFF) as u16;
    packet[4..6].copy_from_slice(&ip_id.to_be_bytes());
    
    packet[6] = 0x40; // Flags: Don't Fragment
    packet[7] = 0x00; // Fragment offset
    packet[8] = ttl;  // TTL
    packet[9] = IPPROTO_TCP as u8; // Protocol: TCP
    // Checksum at [10..12] - will be filled by kernel with IP_HDRINCL
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
    
    // TCP Header
    packet[20..22].copy_from_slice(&src_port.to_be_bytes());
    packet[22..24].copy_from_slice(&dst_port.to_be_bytes());
    packet[24..28].copy_from_slice(&seq.to_be_bytes());
    packet[28..32].copy_from_slice(&0u32.to_be_bytes()); // ACK
    packet[32] = 0x50; // Data offset (5 * 4 = 20 bytes)
    packet[33] = 0x02; // Flags: SYN
    packet[34..36].copy_from_slice(&8192u16.to_be_bytes()); // Window
    // TCP checksum at [36..38] - set to 0 for now
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

/// Enable IP_RECVERR on a socket to receive ICMP errors via MSG_ERRQUEUE
pub fn enable_ip_recverr(fd: RawFd) -> Result<()> {
    eprintln!("[DEBUG enable_ip_recverr] Enabling IP_RECVERR on fd={}", fd);
    let one: c_int = 1;
    let rc = unsafe {
        setsockopt(
            fd,
            SOL_IP,
            IP_RECVERR,
            &one as *const _ as *const c_void,
            std::mem::size_of::<c_int>() as u32,
        )
    };
    if rc != 0 {
        let e = std::io::Error::last_os_error();
        eprintln!("[DEBUG enable_ip_recverr] Failed: {}", e);
        return Err(e).map_err(|e| anyhow!(e));
    }
    
    // Verify IP_RECVERR was set by reading it back
    let mut recverr_val: c_int = 0;
    let mut len: u32 = std::mem::size_of::<c_int>() as u32;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            SOL_IP,
            IP_RECVERR,
            &mut recverr_val as *mut _ as *mut c_void,
            &mut len as *mut u32,
        )
    };
    if rc == 0 {
        eprintln!("[DEBUG enable_ip_recverr] Verified IP_RECVERR readback: {}", recverr_val);
    } else {
        eprintln!("[DEBUG enable_ip_recverr] Failed to read back IP_RECVERR");
    }
    
    eprintln!("[DEBUG enable_ip_recverr] Success");
    Ok(())
}

/// Set IP TTL (Time-To-Live) on a socket
pub fn set_ip_ttl(fd: RawFd, ttl: i32) -> Result<()> {
    eprintln!("[DEBUG set_ip_ttl] Setting TTL={} on fd={}", ttl, fd);
    let rc = unsafe {
        setsockopt(
            fd,
            SOL_IP,
            IP_TTL,
            &ttl as *const _ as *const c_void,
            std::mem::size_of::<i32>() as u32,
        )
    };
    if rc != 0 {
        let e = std::io::Error::last_os_error();
        eprintln!("[DEBUG set_ip_ttl] Failed: {}", e);
        return Err(e).map_err(|e| anyhow!(e));
    }
    
    // Verify TTL was set by reading it back
    let mut read_ttl: i32 = 0;
    let mut len: u32 = std::mem::size_of::<i32>() as u32;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            SOL_IP,
            IP_TTL,
            &mut read_ttl as *mut _ as *mut c_void,
            &mut len as *mut u32,
        )
    };
    if rc == 0 {
        eprintln!("[DEBUG set_ip_ttl] Verified TTL readback: {}", read_ttl);
    }
    
    eprintln!("[DEBUG set_ip_ttl] Success");
    Ok(())
}

/// Non-blocking poll of the kernel error queue for ICMP Time Exceeded router address.
/// We use a small blocking recvmsg via a short-lived async block, but guarded by an outer timeout.
pub async fn poll_errqueue(fd: RawFd) -> Result<Option<String>> {
    // Do a single recvmsg(MSG_ERRQUEUE). This is a blocking syscall;
    // call it inside spawn_blocking so we don't block the Tokio reactor.
    // All structures must be created inside to avoid Send issues with raw pointers
    let res = tokio::task::spawn_blocking(move || {
        eprintln!("[DEBUG poll_errqueue] Starting, fd={}", fd);
        
        // Save original flags and set socket to blocking mode with a receive timeout
        let orig_flags = unsafe { libc::fcntl(fd, libc::F_GETFL, 0) };
        if orig_flags < 0 {
            eprintln!("[DEBUG poll_errqueue] Failed to get socket flags");
            return Err(std::io::Error::last_os_error());
        }
        eprintln!("[DEBUG poll_errqueue] Original flags: 0x{:x}, O_NONBLOCK={}", orig_flags, orig_flags & libc::O_NONBLOCK);
        
        // Set to blocking (remove O_NONBLOCK)
        let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, orig_flags & !libc::O_NONBLOCK) };
        if rc < 0 {
            eprintln!("[DEBUG poll_errqueue] Failed to set blocking mode");
            return Err(std::io::Error::last_os_error());
        }
        
        // Set a receive timeout of 1 second on the socket
        let timeout_val = libc::timeval {
            tv_sec: 1,
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
            eprintln!("[DEBUG poll_errqueue] Failed to set SO_RCVTIMEO");
        } else {
            eprintln!("[DEBUG poll_errqueue] Socket set to blocking mode with 1s timeout");
        }
        
        // Prepare structures inside the blocking task
        let mut cmsg_space = [0u8; 512];
        let mut data_buf = [0u8; 1];
        let mut iov = iovec {
            iov_base: data_buf.as_mut_ptr() as *mut c_void,
            iov_len: data_buf.len(),
        };
        let mut name: sockaddr_in = unsafe { std::mem::zeroed() };
        let mut msg: msghdr = unsafe { std::mem::zeroed() };
        msg.msg_name = &mut name as *mut _ as *mut c_void;
        msg.msg_namelen = std::mem::size_of::<sockaddr_in>() as u32;
        msg.msg_iov = &mut iov as *mut iovec;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_space.as_mut_ptr() as *mut c_void;
        msg.msg_controllen = cmsg_space.len() as _;
        
        eprintln!("[DEBUG poll_errqueue] Calling recvmsg with MSG_ERRQUEUE...");
        
        // First, check if there's anything in the error queue without blocking
        // by trying a non-blocking read first
        let mut peek_msg: msghdr = msg;
        let peek_rc = unsafe { recvmsg(fd, &mut peek_msg as *mut msghdr, MSG_ERRQUEUE | libc::MSG_DONTWAIT) };
        eprintln!("[DEBUG poll_errqueue] Non-blocking peek result: {}", peek_rc);
        if peek_rc >= 0 {
            eprintln!("[DEBUG poll_errqueue] Found data in error queue immediately!");
            // Data is there, the actual read below will get it
        }
        
        // Try multiple times in case ICMP arrives slightly delayed
        let mut attempts = 0;
        let rc = loop {
            let result = unsafe { recvmsg(fd, &mut msg as *mut msghdr, MSG_ERRQUEUE) };
            attempts += 1;
            
            if result >= 0 {
                eprintln!("[DEBUG poll_errqueue] recvmsg success on attempt {}", attempts);
                break result;
            }
            
            let e = std::io::Error::last_os_error();
            if e.kind() != std::io::ErrorKind::WouldBlock && e.kind() != std::io::ErrorKind::TimedOut {
                eprintln!("[DEBUG poll_errqueue] recvmsg hard error: {} (kind: {:?})", e, e.kind());
                // Restore original flags before returning
                let _ = unsafe { libc::fcntl(fd, libc::F_SETFL, orig_flags) };
                return Err(e);
            }
            
            if attempts >= 5 {
                eprintln!("[DEBUG poll_errqueue] recvmsg failed after {} attempts: {} (kind: {:?})", attempts, e, e.kind());
                eprintln!("[DEBUG poll_errqueue] This likely means no ICMP packets are arriving at the socket");
                // Restore original flags before returning
                let _ = unsafe { libc::fcntl(fd, libc::F_SETFL, orig_flags) };
                return Ok(None);
            }
            
            eprintln!("[DEBUG poll_errqueue] Attempt {} failed, retrying...", attempts);
            // Small delay between attempts
            std::thread::sleep(std::time::Duration::from_millis(200));
        };
        
        eprintln!("[DEBUG poll_errqueue] recvmsg returned: {}", rc);
        
        // Restore original flags before returning
        let _ = unsafe { libc::fcntl(fd, libc::F_SETFL, orig_flags) };
        
        eprintln!("[DEBUG poll_errqueue] recvmsg success, controllen={}, namelen={}", msg.msg_controllen, msg.msg_namelen);

        // Walk cmsgs to locate sock_extended_err
        unsafe {
            let mut cmsg_ptr = msg.msg_control as *const cmsghdr;
            let mut remaining = msg.msg_controllen as isize;
            eprintln!("[DEBUG poll_errqueue] Walking control messages, remaining={}", remaining);
            
            while remaining >= std::mem::size_of::<cmsghdr>() as isize && !cmsg_ptr.is_null() {
                let cmsg = &*cmsg_ptr;
                let cmsg_len = cmsg.cmsg_len as isize;
                eprintln!("[DEBUG poll_errqueue] cmsg: level={}, type={}, len={}", 
                    cmsg.cmsg_level, cmsg.cmsg_type, cmsg_len);
                
                if cmsg.cmsg_level == SOL_IP && cmsg.cmsg_type == IP_RECVERR {
                    eprintln!("[DEBUG poll_errqueue] Found IP_RECVERR cmsg");
                    if cmsg_len >= (std::mem::size_of::<cmsghdr>() + std::mem::size_of::<sock_extended_err>()) as isize {
                        let ee_ptr = (cmsg_ptr as *const u8).add(std::mem::size_of::<cmsghdr>())
                            as *const sock_extended_err;
                        let ee = &*ee_ptr;
                        eprintln!("[DEBUG poll_errqueue] sock_extended_err: ee_errno={}, ee_origin={}, ee_type={}, ee_code={}", 
                            ee.ee_errno, ee.ee_origin, ee.ee_type, ee.ee_code);
                        
                        // Check if this is ICMP Time Exceeded
                        if ee.ee_origin == SO_EE_ORIGIN_ICMP && ee.ee_type == ICMP_TIME_EXCEEDED && ee.ee_code == ICMP_EXC_TTL {
                            eprintln!("[DEBUG poll_errqueue] Confirmed ICMP Time Exceeded");
                            // The sender (router) is reported in msg_name for IP_RECVERR
                            let ip = std::net::Ipv4Addr::from(u32::from_be(name.sin_addr.s_addr));
                            eprintln!("[DEBUG poll_errqueue] Router IP from msg_name: {}", ip);
                            return Ok(Some(ip.to_string()));
                        } else {
                            eprintln!("[DEBUG poll_errqueue] Not a Time Exceeded error, ignoring");
                        }
                    }
                }
                
                // advance to next cmsg (CMSG_NXTHDR logic)
                let next = ((cmsg_ptr as usize) + cmsg_len as usize + std::mem::size_of::<usize>()
                    - 1)
                    & !(std::mem::size_of::<usize>() - 1);
                remaining -= next as isize - cmsg_ptr as isize;
                cmsg_ptr = next as *const cmsghdr;
            }
        }
        eprintln!("[DEBUG poll_errqueue] No IP_RECVERR found in control messages");
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
        // Can't test actual socket operations without a real socket
    }
}
