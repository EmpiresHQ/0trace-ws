use anyhow::{anyhow, Result};
use std::os::fd::RawFd;
use libc::{
    c_int, c_void, cmsghdr, iovec, msghdr, recvmsg, setsockopt, sock_extended_err, sockaddr_in,
    IP_RECVERR, IP_TTL, MSG_ERRQUEUE, SOL_IP,
};

// ICMP constants
const ICMP_TIME_EXCEEDED: u8 = 11;
const ICMP_EXC_TTL: u8 = 0;
const SO_EE_ORIGIN_ICMP: u8 = 2;

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
        
        // Save original flags and set socket to blocking mode
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
        eprintln!("[DEBUG poll_errqueue] Socket set to blocking mode");
        
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
        let rc = unsafe { recvmsg(fd, &mut msg as *mut msghdr, MSG_ERRQUEUE) };
        eprintln!("[DEBUG poll_errqueue] recvmsg returned: {}", rc);
        
        // Restore original flags before returning
        let _ = unsafe { libc::fcntl(fd, libc::F_SETFL, orig_flags) };
        
        if rc < 0 {
            let e = std::io::Error::last_os_error();
            eprintln!("[DEBUG poll_errqueue] recvmsg error: {} (kind: {:?})", e, e.kind());
            // EAGAIN/EWOULDBLOCK means no errqueue data
            if e.kind() == std::io::ErrorKind::WouldBlock {
                eprintln!("[DEBUG poll_errqueue] No data in error queue (EWOULDBLOCK)");
                return Ok(None);
            }
            return Err(e);
        }
        
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
