use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use nix::unistd::Pid;

const MAX_SOCKADDR: usize = 128;
const TCP_LISTEN: &str = "0A";
const UNIX_ACCEPTING: u32 = 0x0001_0000;

#[derive(Debug, PartialEq, Eq)]
pub enum Destination {
    Unspecified,
    Kernel,
    Loopback { ip: IpAddr, port: u16 },
    Remote(String),
    UnixPath(Vec<u8>),
    UnixAbstract(Vec<u8>),
    Other(u16),
}

pub fn parse_sockaddr(bytes: &[u8]) -> Destination {
    let Some(family) = bytes.get(..2).map(|family| u16::from_ne_bytes([family[0], family[1]])) else {
        return Destination::Unspecified;
    };
    match i32::from(family) {
        libc::AF_UNSPEC => Destination::Unspecified,
        libc::AF_NETLINK => Destination::Kernel,
        libc::AF_INET if bytes.len() >= 8 => {
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            ip_destination(IpAddr::V4(Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7])), port)
        }
        libc::AF_INET6 if bytes.len() >= 24 => {
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            let octets: [u8; 16] = bytes[8..24].try_into().unwrap();
            ip_destination(IpAddr::V6(Ipv6Addr::from(octets)), port)
        }
        libc::AF_UNIX => {
            let path = &bytes[2..];
            match path.first() {
                None => Destination::Unspecified,
                Some(0) => Destination::UnixAbstract(trim_nul(&path[1..]).to_vec()),
                Some(_) => Destination::UnixPath(trim_nul(path).to_vec()),
            }
        }
        _ => Destination::Other(family),
    }
}

/// Connecting to the unspecified address reaches this host, like loopback.
fn ip_destination(ip: IpAddr, port: u16) -> Destination {
    let local = |v4: Ipv4Addr| v4.is_loopback() || v4.is_unspecified();
    let loopback = match ip {
        IpAddr::V4(v4) => local(v4),
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified() || v6.to_ipv4_mapped().is_some_and(local),
    };
    if loopback { Destination::Loopback { ip, port } } else { Destination::Remote(format!("{ip}:{port}")) }
}

fn trim_nul(bytes: &[u8]) -> &[u8] {
    bytes.iter().position(|&byte| byte == 0).map_or(bytes, |end| &bytes[..end])
}

pub fn read_sockaddr(pid: Pid, address: u64, length: u64) -> Option<Destination> {
    if address == 0 {
        return None;
    }
    let length = (length as usize).min(MAX_SOCKADDR);
    super::tracee::read_exact(pid, address, length).map(|bytes| parse_sockaddr(&bytes))
}

/// A socket of the command known to listen on a loopback port. Checking that
/// it is still open takes one readlink, where finding it again means reading
/// /proc/net and every descriptor of every traced process, for each datagram.
pub struct KnownListeners {
    by_port: HashMap<u16, OpenSocket>,
}

#[derive(Clone, Copy)]
struct OpenSocket {
    pid: Pid,
    fd: i32,
    inode: u64,
}

impl KnownListeners {
    pub fn new() -> Self {
        Self { by_port: HashMap::new() }
    }

    /// Remembers a socket the command has just bound to a loopback port.
    /// Without this it is found when something first connects to the port.
    pub fn bound(&mut self, pid: Pid, fd: i32) {
        if let Some(socket) = Socket::of(pid, fd)
            && let Some(local) = socket.address(libc::getsockname)
            && let Some(inode) = fd_socket_inode(pid, fd)
        {
            self.by_port.insert(local.port(), OpenSocket { pid, fd, inode });
        }
    }

    fn still_listening(&self, port: u16) -> bool {
        self.by_port.get(&port).is_some_and(|socket| fd_socket_inode(socket.pid, socket.fd) == Some(socket.inode))
    }
}

/// Peers that belong to the traced process tree are part of the command itself.
pub fn external_peer(
    pid: Pid,
    destination: &Destination,
    tracees: &[Pid],
    known: &mut KnownListeners,
) -> Option<String> {
    let peer_sockets = match destination {
        Destination::Unspecified | Destination::Kernel => return None,
        Destination::Remote(address) => return Some(format!("network access to {address}")),
        Destination::Other(family) => return Some(format!("uses socket address family {family}")),
        Destination::Loopback { port, .. } if known.still_listening(*port) => return None,
        Destination::Loopback { port, .. } => loopback_listeners(pid, *port),
        Destination::UnixPath(path) => unix_listeners(pid, path, false),
        Destination::UnixAbstract(name) => unix_listeners(pid, name, true),
    };
    let owned = sockets_of(tracees);
    if let Some(listener) = peer_sockets.iter().find_map(|inode| owned.get(inode)) {
        if let Destination::Loopback { port, .. } = destination {
            known.by_port.insert(*port, *listener);
        }
        return None;
    }
    Some(match destination {
        Destination::Loopback { port, .. } => format!("connects to a local service it did not start (port {port})"),
        Destination::UnixPath(path) => {
            format!("connects to a local service it did not start ({})", String::from_utf8_lossy(path))
        }
        _ => "connects to a local service it did not start".to_owned(),
    })
}

/// Taints a connection the command accepted unless it came from a process the
/// command started itself.
/// `opened_by_command` holds the local ends of the connections the command
/// opened, because a client may close its end before the server accepts.
pub fn accepted_from_outside(
    pid: Pid,
    fd: i32,
    tracees: &[Pid],
    opened_by_command: &mut HashSet<SocketAddr>,
) -> Option<String> {
    if let Some(remote) = Socket::of(pid, fd).and_then(|socket| socket.address(libc::getpeername))
        && remote.ip().is_loopback()
        && opened_by_command.remove(&remote)
    {
        return None;
    }
    let inode = fd_socket_inode(pid, fd)?;
    let sockets = inet_sockets(pid);
    let accepted = sockets.iter().find(|socket| socket.inode == inode)?;
    if !accepted.remote.ip().is_loopback() {
        return Some(format!("accepted a connection from {}", accepted.remote));
    }
    if opened_by_command.remove(&accepted.remote) {
        return None;
    }
    let owned = sockets_of(tracees);
    let from_command =
        sockets.iter().any(|socket| socket.local == accepted.remote && owned.contains_key(&socket.inode));
    (!from_command).then(|| format!("accepted a connection from a process it did not start ({})", accepted.remote))
}

/// The local address of an internet socket.
pub fn local_address(pid: Pid, fd: i32) -> Option<SocketAddr> {
    if let Some(local) = Socket::of(pid, fd).and_then(|socket| socket.address(libc::getsockname)) {
        return Some(local);
    }
    let inode = fd_socket_inode(pid, fd)?;
    inet_sockets(pid).into_iter().find(|socket| socket.inode == inode).map(|socket| socket.local)
}

/// A copy of a socket of the command, which the kernel answers questions
/// about directly. Without one, the answers are searched for in /proc/net.
struct Socket(OwnedFd);

type AddressOf = unsafe extern "C" fn(libc::c_int, *mut libc::sockaddr, *mut libc::socklen_t) -> libc::c_int;

impl Socket {
    /// None before Linux 5.6, or if `fd` is not a socket of the thread: the
    /// copy comes from its process, and a thread can have descriptors of its own.
    fn of(pid: Pid, fd: i32) -> Option<Self> {
        let copy = super::tracee::copy_descriptor(pid, fd).ok()?;
        let inode = fs::File::from(copy.try_clone().ok()?).metadata().ok()?.ino();
        (fd_socket_inode(pid, fd) == Some(inode)).then_some(Self(copy))
    }

    /// The address `getsockname` or `getpeername` gives, if it is an internet address.
    fn address(&self, address_of: AddressOf) -> Option<SocketAddr> {
        let mut storage = [0u8; MAX_SOCKADDR];
        let mut length = MAX_SOCKADDR as libc::socklen_t;
        // SAFETY: the kernel writes at most `length` bytes into `storage`.
        if unsafe { address_of(self.0.as_raw_fd(), storage.as_mut_ptr().cast(), &mut length) } != 0 {
            return None;
        }
        match parse_sockaddr(&storage[..(length as usize).min(MAX_SOCKADDR)]) {
            Destination::Loopback { ip, port } => Some(SocketAddr::new(without_ipv4_mapping(ip), port)),
            Destination::Remote(address) => address
                .parse()
                .ok()
                .map(|address: SocketAddr| SocketAddr::new(without_ipv4_mapping(address.ip()), address.port())),
            _ => None,
        }
    }

    fn is_datagram(&self) -> bool {
        let mut kind: libc::c_int = 0;
        let mut length = size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: the kernel writes one int into `kind`.
        let result = unsafe {
            libc::getsockopt(self.0.as_raw_fd(), libc::SOL_SOCKET, libc::SO_TYPE, (&raw mut kind).cast(), &mut length)
        };
        result == 0 && kind == libc::SOCK_DGRAM
    }
}

/// /proc/net shows IPv4-mapped addresses as IPv4, and both ends of a
/// connection have to compare equal.
fn without_ipv4_mapping(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

struct InetSocket {
    local: SocketAddr,
    remote: SocketAddr,
    listening: bool,
    connectionless: bool,
    inode: u64,
}

/// The path of a `listen` input: a protocol and a loopback address.
pub fn port_key(datagram: bool, address: SocketAddr) -> PathBuf {
    PathBuf::from(format!("{}:{address}", if datagram { "udp" } else { "tcp" }))
}

/// Whether anything is bound where a `listen` input points, or None if the key
/// is not one. A socket bound to the unspecified address takes connections to
/// any address on its port.
pub fn is_bound(key: &Path) -> Option<bool> {
    let (protocol, address) = key.to_str()?.split_once(':')?;
    let address: SocketAddr = address.parse().ok()?;
    let datagram = match protocol {
        "udp" => true,
        "tcp" => false,
        _ => return None,
    };
    let reaches = |local: SocketAddr| {
        local.port() == address.port()
            && (local.ip() == address.ip() || local.ip().is_unspecified() || address.ip().is_unspecified())
    };
    let sockets = inet_sockets(nix::unistd::getpid());
    Some(sockets.iter().any(|socket| socket.connectionless == datagram && socket.listening && reaches(socket.local)))
}

/// Whether `fd` is a datagram socket and no other socket is bound to `port`.
pub fn datagram_to_nobody(pid: Pid, fd: i32, port: u16) -> bool {
    if Socket::of(pid, fd).is_some_and(|socket| !socket.is_datagram()) {
        return false;
    }
    let Some(inode) = fd_socket_inode(pid, fd) else {
        return false;
    };
    let sockets = inet_sockets(pid);
    let is_datagram = sockets.iter().any(|socket| socket.inode == inode && socket.connectionless);
    is_datagram
        && !sockets.iter().any(|socket| socket.inode != inode && socket.local.port() == port && socket.listening)
}

fn loopback_listeners(pid: Pid, port: u16) -> Vec<u64> {
    inet_sockets(pid)
        .into_iter()
        .filter(|socket| socket.local.port() == port && socket.listening)
        .map(|socket| socket.inode)
        .collect()
}

fn inet_sockets(pid: Pid) -> Vec<InetSocket> {
    let mut sockets = Vec::new();
    for (table, connectionless) in [("tcp", false), ("tcp6", false), ("udp", true), ("udp6", true)] {
        let Ok(contents) = fs::read_to_string(format!("/proc/{pid}/net/{table}")) else {
            continue;
        };
        for line in contents.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let (Some(local), Some(remote), Some(state), Some(inode)) =
                (fields.get(1), fields.get(2), fields.get(3), fields.get(9))
            else {
                continue;
            };
            let (Some(local), Some(remote), Ok(inode)) =
                (parse_proc_address(local), parse_proc_address(remote), inode.parse())
            else {
                continue;
            };
            sockets.push(InetSocket {
                local,
                remote,
                listening: connectionless || *state == TCP_LISTEN,
                connectionless,
                inode,
            });
        }
    }
    sockets
}

/// Parses `0100007F:1F90` (IPv4) or a 32-digit IPv6 address from /proc/net,
/// where each 32-bit word is in host byte order. IPv4-mapped addresses are
/// normalized to IPv4 so both ends of a connection compare equal.
fn parse_proc_address(field: &str) -> Option<SocketAddr> {
    let (address, port) = field.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let word =
        |index: usize| u32::from_str_radix(address.get(index * 8..index * 8 + 8)?, 16).ok().map(u32::to_ne_bytes);
    let ip = match address.len() {
        8 => IpAddr::V4(Ipv4Addr::from(word(0)?)),
        32 => {
            let mut octets = [0u8; 16];
            for index in 0..4 {
                octets[index * 4..index * 4 + 4].copy_from_slice(&word(index)?);
            }
            let v6 = Ipv6Addr::from(octets);
            v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4)
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

fn unix_listeners(pid: Pid, name: &[u8], is_abstract: bool) -> Vec<u64> {
    let Ok(contents) = fs::read_to_string(format!("/proc/{pid}/net/unix")) else {
        return Vec::new();
    };
    let expected = if is_abstract {
        format!("@{}", String::from_utf8_lossy(name))
    } else {
        String::from_utf8_lossy(name).into_owned()
    };
    let mut inodes = Vec::new();
    for line in contents.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let (Some(flags), Some(inode), Some(path)) = (fields.get(3), fields.get(6), fields.get(7)) else {
            continue;
        };
        let flags = u32::from_str_radix(flags, 16).unwrap_or(0);
        let is_stream_listener = flags & UNIX_ACCEPTING != 0;
        let is_datagram = fields.get(4) == Some(&"0002");
        if *path == expected && (is_stream_listener || is_datagram) {
            inodes.extend(inode.parse::<u64>());
        }
    }
    inodes
}

/// The sockets the traced processes hold, by inode.
fn sockets_of(tracees: &[Pid]) -> HashMap<u64, OpenSocket> {
    let mut sockets = HashMap::new();
    for &pid in tracees {
        let Ok(fds) = fs::read_dir(format!("/proc/{pid}/fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            let Some(fd) = fd.file_name().to_str().and_then(|name| name.parse().ok()) else {
                continue;
            };
            if let Some(inode) = fd_socket_inode(pid, fd) {
                sockets.insert(inode, OpenSocket { pid, fd, inode });
            }
        }
    }
    sockets
}

fn fd_socket_inode(pid: Pid, fd: i32) -> Option<u64> {
    socket_inode(&fs::read_link(format!("/proc/{pid}/fd/{fd}")).ok()?.to_string_lossy())
}

fn socket_inode(link: &str) -> Option<u64> {
    link.strip_prefix("socket:[")?.strip_suffix(']')?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inet(ip: [u8; 4], port: u16) -> Vec<u8> {
        let mut bytes = (libc::AF_INET as u16).to_ne_bytes().to_vec();
        bytes.extend(port.to_be_bytes());
        bytes.extend(ip);
        bytes.extend([0; 8]);
        bytes
    }

    #[test]
    fn classifies_destinations() {
        assert_eq!(
            parse_sockaddr(&inet([127, 0, 0, 1], 8080)),
            Destination::Loopback { ip: Ipv4Addr::LOCALHOST.into(), port: 8080 }
        );
        assert_eq!(parse_sockaddr(&inet([1, 1, 1, 1], 53)), Destination::Remote("1.1.1.1:53".into()));
        assert_eq!(
            parse_sockaddr(&inet([0, 0, 0, 0], 9123)),
            Destination::Loopback { ip: Ipv4Addr::UNSPECIFIED.into(), port: 9123 }
        );

        let mut unix = (libc::AF_UNIX as u16).to_ne_bytes().to_vec();
        unix.extend(b"/run/docker.sock\0");
        assert_eq!(parse_sockaddr(&unix), Destination::UnixPath(b"/run/docker.sock".to_vec()));
    }

    #[test]
    fn parses_proc_net_addresses() {
        assert_eq!(parse_proc_address("0100007F:1F90"), Some("127.0.0.1:8080".parse().unwrap()));
        assert_eq!(parse_proc_address("0000000000000000FFFF00000100007F:0050"), Some("127.0.0.1:80".parse().unwrap()));
    }

    #[test]
    fn connection_accepted_from_own_client_is_not_external() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let _client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (accepted, _) = listener.accept().unwrap();
        let me = nix::unistd::getpid();
        let fd = std::os::fd::AsRawFd::as_raw_fd(&accepted);
        assert_eq!(accepted_from_outside(me, fd, &[me], &mut HashSet::new()), None);
        assert!(accepted_from_outside(me, fd, &[], &mut HashSet::new()).is_some());
    }

    #[test]
    fn connection_from_a_client_that_already_closed_is_not_external() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let me = nix::unistd::getpid();
        let client_end = local_address(me, std::os::fd::AsRawFd::as_raw_fd(&client)).unwrap();
        drop(client);
        let (accepted, _) = listener.accept().unwrap();
        let fd = std::os::fd::AsRawFd::as_raw_fd(&accepted);
        assert!(accepted_from_outside(me, fd, &[me], &mut HashSet::new()).is_some());
        assert_eq!(accepted_from_outside(me, fd, &[me], &mut HashSet::from([client_end])), None);
    }

    #[test]
    fn listener_in_own_process_is_not_external() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let me = nix::unistd::getpid();
        assert_eq!(
            external_peer(
                me,
                &Destination::Loopback { ip: Ipv4Addr::LOCALHOST.into(), port },
                &[me],
                &mut KnownListeners::new()
            ),
            None
        );
        assert!(
            external_peer(
                me,
                &Destination::Loopback { ip: Ipv4Addr::LOCALHOST.into(), port },
                &[],
                &mut KnownListeners::new()
            )
            .is_some()
        );
    }

    #[test]
    fn a_known_listener_counts_only_while_it_is_open() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let me = nix::unistd::getpid();
        let mut known = KnownListeners::new();
        assert_eq!(
            external_peer(me, &Destination::Loopback { ip: Ipv4Addr::LOCALHOST.into(), port }, &[me], &mut known),
            None
        );
        assert!(known.still_listening(port));
        drop(listener);
        assert!(!known.still_listening(port));
        assert!(
            external_peer(me, &Destination::Loopback { ip: Ipv4Addr::LOCALHOST.into(), port }, &[me], &mut known)
                .is_some()
        );
    }
}
