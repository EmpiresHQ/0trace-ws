use anyhow::{anyhow, Result};
use std::os::fd::RawFd;
use libc::{
    c_int, c_void, cmsghdr, iovec, msghdr, recvmsg, setsockopt, sock_extended_err, sockaddr_in,
    IP_RECVERR, IP_TTL, MSG_ERRQUEUE, SOL_IP,
};

/// Enable IP_RECVERR on a socket to receive ICMP errors via MSG_ERRQUEUE
pub fn enable_ip_recverr(fd: RawFd) -> Result<()> {
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
        return Err(std::io::Error::last_os_error()).map_err(|e| anyhow!(e));
    }
    Ok(())
}

/// Set IP TTL (Time-To-Live) on a socket
pub fn set_ip_ttl(fd: RawFd, ttl: i32) -> Result<()> {
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
        return Err(std::io::Error::last_os_error()).map_err(|e| anyhow!(e));
    }
    Ok(())
}

/// Non-blocking poll of the kernel error queue for ICMP Time Exceeded router address.
/// We use a small blocking recvmsg via a short-lived async block, but guarded by an outer timeout.
pub async fn poll_errqueue(fd: RawFd) -> Result<Option<String>> {
    // Do a single recvmsg(MSG_ERRQUEUE). This is a blocking syscall;
    // call it inside spawn_blocking so we don't block the Tokio reactor.
    // All structures must be created inside to avoid Send issues with raw pointers
    let res = tokio::task::spawn_blocking(move || {
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
        msg.msg_controllen = cmsg_space.len();
        
        let rc = unsafe { recvmsg(fd, &mut msg as *mut msghdr, MSG_ERRQUEUE) };
        if rc < 0 {
            let e = std::io::Error::last_os_error();
            // EAGAIN/EWOULDBLOCK means no errqueue data
            if e.kind() == std::io::ErrorKind::WouldBlock {
                return Ok(None);
            }
            return Err(e);
        }

        // Walk cmsgs to locate sock_extended_err
        unsafe {
            let mut cmsg_ptr = msg.msg_control as *const cmsghdr;
            let mut remaining = msg.msg_controllen as isize;
            while remaining >= std::mem::size_of::<cmsghdr>() as isize && !cmsg_ptr.is_null() {
                let cmsg = &*cmsg_ptr;
                let cmsg_len = cmsg.cmsg_len as isize;
                if cmsg_len
                    >= (std::mem::size_of::<cmsghdr>() + std::mem::size_of::<sock_extended_err>())
                        as isize
                {
                    let ee_ptr = (cmsg_ptr as *const u8).add(std::mem::size_of::<cmsghdr>())
                        as *const sock_extended_err;
                    let _ee = &*ee_ptr;
                    // The sender (router) is reported in msg_name for IP_RECVERR
                    let ip = std::net::Ipv4Addr::from(u32::from_be(name.sin_addr.s_addr));
                    return Ok(Some(ip.to_string()));
                }
                // advance to next cmsg (CMSG_NXTHDR logic)
                let next = ((cmsg_ptr as usize) + cmsg_len as usize + std::mem::size_of::<usize>()
                    - 1)
                    & !(std::mem::size_of::<usize>() - 1);
                remaining -= next as isize - cmsg_ptr as isize;
                cmsg_ptr = next as *const cmsghdr;
            }
        }
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
