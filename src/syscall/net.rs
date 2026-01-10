use alloc::sync::Arc;
use core::mem::size_of;

use crate::fs::{File, NetSocketFile};
use crate::mm::{read_user_value, write_user_value};
use crate::task::processor::current_process;
use crate::trap::get_current_token;

const AF_INET: u16 = 2;

const SOCK_STREAM: usize = 1;
const SOCK_DGRAM: usize = 2;
const SOCK_NONBLOCK: usize = 0x800;
const SOCK_CLOEXEC: usize = 0x80000;
const O_NONBLOCK: u32 = 0x800;
const FD_CLOEXEC: u32 = 1;

const SOL_SOCKET: usize = 1;
const SO_SNDBUF: usize = 7;
const SO_RCVBUF: usize = 8;

const EINVAL: isize = -22;
const EBADF: isize = -9;
const EAFNOSUPPORT: isize = -97;
const EPROTONOSUPPORT: isize = -93;
const ENOTSOCK: isize = -88;
const EOPNOTSUPP: isize = -95;
const EISCONN: isize = -106;
const EMFILE: isize = -24;

#[repr(C)]
#[derive(Clone, Copy)]
struct SockAddrIn {
    sin_family: u16,
    sin_port: u16, // network byte order
    sin_addr: u32, // network byte order
    sin_zero: [u8; 8],
}

fn get_file(fd: usize) -> Result<Arc<dyn File + Send + Sync>, isize> {
    let process = current_process();
    let inner = process.borrow_mut();
    if fd >= inner.fd_table.len() {
        return Err(EBADF);
    }
    inner.fd_table[fd].clone().ok_or(EBADF)
}

fn parse_sockaddr_in(user_ptr: usize, len: usize) -> Result<(smoltcp::wire::Ipv4Address, u16), isize> {
    if user_ptr == 0 || len < size_of::<SockAddrIn>() {
        return Err(EINVAL);
    }
    let token = get_current_token();
    let sa = read_user_value(token, user_ptr as *const SockAddrIn);
    if sa.sin_family != AF_INET {
        return Err(EAFNOSUPPORT);
    }
    let port = u16::from_be(sa.sin_port);
    let ip_raw = u32::from_be(sa.sin_addr);
    let ip = smoltcp::wire::Ipv4Address::from_bytes(&ip_raw.to_be_bytes());
    Ok((ip, port))
}

fn write_sockaddr_in(user_ptr: usize, user_len_ptr: usize, ip: smoltcp::wire::Ipv4Address, port: u16) {
    if user_ptr == 0 || user_len_ptr == 0 {
        return;
    }
    let token = get_current_token();
    let mut len = read_user_value(token, user_len_ptr as *const u32) as usize;
    if len < size_of::<SockAddrIn>() {
        // Write back required size anyway.
        len = size_of::<SockAddrIn>();
        write_user_value(token, user_len_ptr as *mut u32, &(len as u32));
        return;
    }
    let sa = SockAddrIn {
        sin_family: AF_INET,
        sin_port: port.to_be(),
        sin_addr: {
            let b = ip.as_bytes();
            u32::from_be_bytes([b[0], b[1], b[2], b[3]]).to_be()
        },
        sin_zero: [0; 8],
    };
    write_user_value(token, user_ptr as *mut SockAddrIn, &sa);
    write_user_value(token, user_len_ptr as *mut u32, &(size_of::<SockAddrIn>() as u32));
}

pub fn syscall_socket(domain: usize, socket_type: usize, _protocol: usize) -> isize {
    if domain as u16 != AF_INET {
        return EAFNOSUPPORT;
    }
    let st = socket_type & 0xff;
    let cloexec = (socket_type & SOCK_CLOEXEC) != 0;
    let nonblock = (socket_type & SOCK_NONBLOCK) != 0;
    let file: Arc<dyn File + Send + Sync> = match st {
        SOCK_STREAM => NetSocketFile::new_tcp(),
        SOCK_DGRAM => NetSocketFile::new_udp(),
        _ => return EPROTONOSUPPORT,
    };
    let process = current_process();
    let mut inner = process.borrow_mut();
    let Some(fd) = inner.alloc_fd() else {
        return EMFILE;
    };
    inner.fd_table[fd] = Some(file);
    let mut fd_flags = 0u32;
    if cloexec {
        fd_flags |= FD_CLOEXEC;
    }
    if nonblock {
        fd_flags |= O_NONBLOCK;
    }
    inner.fd_flags[fd] = fd_flags;
    if crate::debug_config::DEBUG_NET {
        crate::println!("[net] pid={} socket() -> fd={} type={}", process.pid.0, fd, st);
    }
    fd as isize
}

pub fn syscall_bind(fd: usize, addr: usize, addrlen: usize) -> isize {
    let file = match get_file(fd) {
        Ok(f) => f,
        Err(e) => return e,
    };
    let sock = match file.as_any().downcast_ref::<NetSocketFile>() {
        Some(s) => s,
        None => return ENOTSOCK,
    };
    let (ip, port) = match parse_sockaddr_in(addr, addrlen) {
        Ok(v) => v,
        Err(e) => return e,
    };
    // 0.0.0.0 means "any"; in loopback-only setup treat as 127.0.0.1.
    let ip = if ip == smoltcp::wire::Ipv4Address::UNSPECIFIED {
        smoltcp::wire::Ipv4Address::new(127, 0, 0, 1)
    } else {
        ip
    };
    let r = match sock.bind_v4(ip, port) {
        Ok(()) => 0,
        Err(e) => e,
    };
    if crate::debug_config::DEBUG_NET {
        crate::println!("[net] pid={} bind(fd={}) -> {}:{} = {}", current_process().pid.0, fd, ip, port, r);
    }
    r
}

pub fn syscall_listen(fd: usize, backlog: usize) -> isize {
    let file = match get_file(fd) {
        Ok(f) => f,
        Err(e) => return e,
    };
    let sock = match file.as_any().downcast_ref::<NetSocketFile>() {
        Some(s) => s,
        None => return ENOTSOCK,
    };
    match sock.listen(backlog) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

pub fn syscall_accept(fd: usize, addr: usize, addrlen: usize) -> isize {
    let file = match get_file(fd) {
        Ok(f) => f,
        Err(e) => return e,
    };
    let sock = match file.as_any().downcast_ref::<NetSocketFile>() {
        Some(s) => s,
        None => return ENOTSOCK,
    };
    let Ok(new_sock) = sock.accept() else {
        return EOPNOTSUPP;
    };
    let peer = new_sock.tcp_endpoints_v4();
    let process = current_process();
    let mut inner = process.borrow_mut();
    if fd >= inner.fd_flags.len() {
        let len = inner.fd_table.len();
        inner.fd_flags.resize(len, 0);
    }
    let mut inherited_flags = inner.fd_flags.get(fd).copied().unwrap_or(0);
    inherited_flags &= !FD_CLOEXEC;
    let Some(newfd) = inner.alloc_fd() else {
        return EMFILE;
    };
    inner.fd_table[newfd] = Some(new_sock);
    inner.fd_flags[newfd] = inherited_flags;
    drop(inner);
    if let Some((_lip, _lport, rip, rport)) = peer {
        write_sockaddr_in(addr, addrlen, rip, rport);
    }
    newfd as isize
}

pub fn syscall_connect(fd: usize, addr: usize, addrlen: usize) -> isize {
    let file = match get_file(fd) {
        Ok(f) => f,
        Err(e) => return e,
    };
    let sock = match file.as_any().downcast_ref::<NetSocketFile>() {
        Some(s) => s,
        None => return ENOTSOCK,
    };
    let (ip, port) = match parse_sockaddr_in(addr, addrlen) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if crate::debug_config::DEBUG_NET {
        crate::println!("[net] pid={} connect(fd={}) -> {}:{}", current_process().pid.0, fd, ip, port);
    }
    match sock.connect_v4(ip, port, None) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

pub fn syscall_sendto(
    fd: usize,
    buf_ptr: usize,
    len: usize,
    _flags: usize,
    addr: usize,
    addrlen: usize,
) -> isize {
    let file = match get_file(fd) {
        Ok(f) => f,
        Err(e) => return e,
    };
    let sock = match file.as_any().downcast_ref::<NetSocketFile>() {
        Some(s) => s,
        None => return ENOTSOCK,
    };
    if len == 0 {
        return 0;
    }
    let token = get_current_token();
    let mut kbuf = alloc::vec![0u8; len];
    crate::mm::copy_from_user(token, buf_ptr as *const u8, kbuf.as_mut_slice());
    match sock.kind() {
        crate::fs::NetSocketKind::TcpStream => {
            // Linux: send()/sendto() on a connected TCP socket ignores the dest address.
            if addr != 0 && addrlen != 0 {
                return EISCONN;
            }
            match sock.tcp_send(&kbuf) {
                Ok(n) => n as isize,
                Err(e) => e,
            }
        }
        crate::fs::NetSocketKind::Udp => {
            if addr == 0 || addrlen == 0 {
                match sock.udp_send_connected(&kbuf) {
                    Ok(n) => n as isize,
                    Err(e) => e,
                }
            } else {
                let (ip, port) = match parse_sockaddr_in(addr, addrlen) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                match sock.udp_send_to_v4(ip, port, &kbuf) {
                    Ok(n) => n as isize,
                    Err(e) => e,
                }
            }
        }
        crate::fs::NetSocketKind::TcpListener => EOPNOTSUPP,
    }
}

pub fn syscall_recvfrom(
    fd: usize,
    buf_ptr: usize,
    len: usize,
    _flags: usize,
    addr: usize,
    addrlen: usize,
) -> isize {
    let file = match get_file(fd) {
        Ok(f) => f,
        Err(e) => return e,
    };
    let sock = match file.as_any().downcast_ref::<NetSocketFile>() {
        Some(s) => s,
        None => return ENOTSOCK,
    };
    if len == 0 {
        return 0;
    }
    match sock.kind() {
        crate::fs::NetSocketKind::TcpStream => {
            let mut kbuf = alloc::vec![0u8; len];
            let n = match sock.tcp_recv(&mut kbuf) {
                Ok(n) => n,
                Err(e) => return e,
            };
            let token = get_current_token();
            crate::mm::copy_to_user(token, buf_ptr as *mut u8, &kbuf[..n]);
            if addr != 0 && addrlen != 0 {
                if let Some((_lip, _lport, rip, rport)) = sock.tcp_endpoints_v4() {
                    write_sockaddr_in(addr, addrlen, rip, rport);
                }
            }
            n as isize
        }
        crate::fs::NetSocketKind::Udp => {
            let mut kbuf = alloc::vec![0u8; len];
            let (n, ip, port) = match sock.udp_recv_from(&mut kbuf) {
                Ok(v) => v,
                Err(e) => return e,
            };
            let token = get_current_token();
            crate::mm::copy_to_user(token, buf_ptr as *mut u8, &kbuf[..n]);
            if addr != 0 && addrlen != 0 {
                write_sockaddr_in(addr, addrlen, ip, port);
            }
            n as isize
        }
        crate::fs::NetSocketKind::TcpListener => EOPNOTSUPP,
    }
}

pub fn syscall_getsockname(fd: usize, addr: usize, addrlen: usize) -> isize {
    let file = match get_file(fd) {
        Ok(f) => f,
        Err(e) => return e,
    };
    let sock = match file.as_any().downcast_ref::<NetSocketFile>() {
        Some(s) => s,
        None => return ENOTSOCK,
    };
    if let Some((lip, lport, _rip, _rport)) = sock.tcp_endpoints_v4() {
        write_sockaddr_in(addr, addrlen, lip, lport);
        return 0;
    }
    if let Some((lip, lport)) = sock.tcp_local_endpoint_v4() {
        write_sockaddr_in(addr, addrlen, lip, lport);
        return 0;
    }
    if let Some((ip, port)) = sock.udp_endpoint_v4() {
        write_sockaddr_in(addr, addrlen, ip, port);
        return 0;
    }
    EOPNOTSUPP
}

pub fn syscall_getpeername(fd: usize, addr: usize, addrlen: usize) -> isize {
    let file = match get_file(fd) {
        Ok(f) => f,
        Err(e) => return e,
    };
    let sock = match file.as_any().downcast_ref::<NetSocketFile>() {
        Some(s) => s,
        None => return ENOTSOCK,
    };
    if let Some((_lip, _lport, rip, rport)) = sock.tcp_endpoints_v4() {
        write_sockaddr_in(addr, addrlen, rip, rport);
        return 0;
    }
    if let Some((rip, rport)) = sock.udp_peer_v4() {
        write_sockaddr_in(addr, addrlen, rip, rport);
        return 0;
    }
    EOPNOTSUPP
}

pub fn syscall_setsockopt(
    fd: usize,
    level: usize,
    optname: usize,
    optval: usize,
    optlen: usize,
) -> isize {
    let file = match get_file(fd) {
        Ok(f) => f,
        Err(e) => return e,
    };
    let sock = match file.as_any().downcast_ref::<NetSocketFile>() {
        Some(s) => s,
        None => return ENOTSOCK,
    };
    if level != SOL_SOCKET {
        return 0;
    }
    if optval == 0 || optlen < size_of::<i32>() {
        return EINVAL;
    }
    let token = get_current_token();
    let v = read_user_value(token, optval as *const i32);
    if v <= 0 {
        return 0;
    }
    let v = v as u32;
    if crate::debug_config::DEBUG_NET && (optname == SO_SNDBUF || optname == SO_RCVBUF) {
        crate::println!("[net] pid={} setsockopt(fd={}, opt={}) = {}", current_process().pid.0, fd, optname, v);
    }
    match optname {
        SO_SNDBUF => sock.set_sockbuf(Some(v), None),
        SO_RCVBUF => sock.set_sockbuf(None, Some(v)),
        _ => {}
    }
    0
}

pub fn syscall_getsockopt(
    fd: usize,
    level: usize,
    optname: usize,
    optval: usize,
    optlen: usize,
) -> isize {
    // `optlen` is a user pointer to socklen_t.
    let token = get_current_token();
    if optlen == 0 {
        return EINVAL;
    }
    let user_len = read_user_value(token, optlen as *const u32) as usize;
    if user_len < size_of::<u32>() {
        write_user_value(token, optlen as *mut u32, &(size_of::<u32>() as u32));
        return EINVAL;
    }
    let file = match get_file(fd) {
        Ok(f) => f,
        Err(e) => return e,
    };
    let sock = match file.as_any().downcast_ref::<NetSocketFile>() {
        Some(s) => s,
        None => return ENOTSOCK,
    };
    let val = if level == SOL_SOCKET {
        match optname {
            SO_SNDBUF => sock.getsockopt_sndbuf(),
            SO_RCVBUF => sock.getsockopt_rcvbuf(),
            _ => 0,
        }
    } else {
        0
    };
    if crate::debug_config::DEBUG_NET && (optname == SO_SNDBUF || optname == SO_RCVBUF) {
        crate::println!("[net] pid={} getsockopt(fd={}, opt={}) -> {}", current_process().pid.0, fd, optname, val);
    }
    if optval != 0 {
        let v: u32 = val;
        write_user_value(token, optval as *mut u32, &v);
    }
    write_user_value(token, optlen as *mut u32, &(size_of::<u32>() as u32));
    0
}

pub fn syscall_shutdown(_fd: usize, _how: usize) -> isize {
    let file = match get_file(_fd) {
        Ok(f) => f,
        Err(e) => return e,
    };
    let sock = match file.as_any().downcast_ref::<NetSocketFile>() {
        Some(s) => s,
        None => return ENOTSOCK,
    };
    if sock.kind() == crate::fs::NetSocketKind::TcpStream {
        let _ = sock.tcp_close();
    }
    0
}
