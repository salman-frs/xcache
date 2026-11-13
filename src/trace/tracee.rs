use std::ffi::OsStr;
use std::fs;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use nix::unistd::Pid;

use super::directories::WorkingDirectories;

const PTRACE_GET_SYSCALL_INFO: libc::c_uint = 0x420e;
const OP_EXIT: u8 = 2;
const OP_SECCOMP: u8 = 3;
const PATH_MAX: usize = 4096;
const PAGE: u64 = 4096;

#[repr(C)]
#[derive(Default)]
struct RawSyscallInfo {
    op: u8,
    _pad: [u8; 3],
    arch: u32,
    _instruction_pointer: u64,
    _stack_pointer: u64,
    data: [u64; 8],
}

pub struct SeccompStop {
    pub arch: u32,
    pub nr: u64,
    pub args: [u64; 6],
    pub ret_data: u32,
}

fn syscall_info(pid: Pid) -> io::Result<RawSyscallInfo> {
    let mut info = RawSyscallInfo::default();
    // SAFETY: the kernel writes at most size_of::<RawSyscallInfo>() bytes.
    let written = unsafe {
        libc::ptrace(
            PTRACE_GET_SYSCALL_INFO,
            pid.as_raw(),
            std::mem::size_of::<RawSyscallInfo>(),
            &mut info as *mut RawSyscallInfo,
        )
    };
    if written < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(info)
}

pub fn seccomp_stop(pid: Pid) -> io::Result<SeccompStop> {
    let info = syscall_info(pid)?;
    if info.op != OP_SECCOMP {
        return Err(io::Error::other("not a seccomp stop"));
    }
    let [nr, a0, a1, a2, a3, a4, a5, ret_data] = info.data;
    Ok(SeccompStop { arch: info.arch, nr, args: [a0, a1, a2, a3, a4, a5], ret_data: ret_data as u32 })
}

pub fn syscall_result(pid: Pid) -> io::Result<i64> {
    let info = syscall_info(pid)?;
    if info.op != OP_EXIT {
        return Err(io::Error::other("not a syscall exit stop"));
    }
    Ok(info.data[0] as i64)
}

/// The call a thread stopped for a signal will run again if the signal is
/// not delivered. x86_64 shows that as the result -ERESTARTSYS; on aarch64
/// the kernel has already moved the PC back to the `svc`.
pub fn restartable_call(pid: Pid) -> Option<(u64, [u64; 6])> {
    let regs = registers(pid)?;
    #[cfg(target_arch = "x86_64")]
    {
        const ERESTARTSYS: i64 = 512;
        (regs.rax as i64 == -ERESTARTSYS)
            .then_some((regs.orig_rax, [regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9]))
    }
    #[cfg(target_arch = "aarch64")]
    {
        const SVC_0: [u8; 4] = 0xd400_0001_u32.to_le_bytes();
        let [a0, a1, a2, a3, a4, a5, ..] = regs.regs;
        (read_exact(pid, regs.pc, 4)? == SVC_0).then_some((regs.regs[8], [a0, a1, a2, a3, a4, a5]))
    }
}

fn registers(pid: Pid) -> Option<libc::user_regs_struct> {
    const NT_PRSTATUS: libc::c_int = 1;
    // SAFETY: user_regs_struct is plain data the kernel fills.
    let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
    let mut iov = libc::iovec { iov_base: (&raw mut regs).cast(), iov_len: size_of::<libc::user_regs_struct>() };
    // SAFETY: the kernel writes at most iov_len bytes into regs.
    let read = unsafe { libc::ptrace(libc::PTRACE_GETREGSET, pid.as_raw(), NT_PRSTATUS, &mut iov) };
    (read == 0 && iov.iov_len == size_of::<libc::user_regs_struct>()).then_some(regs)
}

/// Set once the kernel has refused to show a tracee's memory, which a process
/// that makes itself undumpable causes. The calls it made went unrecorded.
static MEMORY_WAS_HIDDEN: AtomicBool = AtomicBool::new(false);

pub fn memory_was_hidden() -> bool {
    MEMORY_WAS_HIDDEN.load(Ordering::Relaxed)
}

pub fn read_memory(pid: Pid, address: u64, buffer: &mut [u8]) -> io::Result<usize> {
    let local = libc::iovec { iov_base: buffer.as_mut_ptr().cast(), iov_len: buffer.len() };
    let remote = libc::iovec { iov_base: address as *mut libc::c_void, iov_len: buffer.len() };
    // SAFETY: both iovecs describe valid ranges; the remote one is only read.
    let read = unsafe { libc::process_vm_readv(pid.as_raw(), &local, 1, &remote, 1, 0) };
    if read >= 0 {
        return Ok(read as usize);
    }
    let error = io::Error::last_os_error();
    let call_fails_too = error.raw_os_error() == Some(libc::EFAULT);
    let thread_is_gone = error.raw_os_error() == Some(libc::ESRCH);
    if !call_fails_too && !thread_is_gone {
        MEMORY_WAS_HIDDEN.store(true, Ordering::Relaxed);
    }
    Err(error)
}

pub fn read_exact(pid: Pid, address: u64, length: usize) -> Option<Vec<u8>> {
    let mut buffer = vec![0; length];
    (read_memory(pid, address, &mut buffer).ok()? == length).then_some(buffer)
}

/// Reads a NUL-terminated string page by page, so a string that ends just
/// before an unmapped page is still read.
pub fn read_c_string(pid: Pid, address: u64) -> Option<Vec<u8>> {
    if address == 0 {
        return None;
    }
    let mut bytes = Vec::new();
    let mut cursor = address;
    let mut page = [0; PAGE as usize];
    while bytes.len() < PATH_MAX {
        let until_page_end = (PAGE - cursor % PAGE) as usize;
        let chunk = &mut page[..until_page_end.min(PATH_MAX - bytes.len())];
        let read = read_memory(pid, cursor, chunk).ok()?;
        if read == 0 {
            return None;
        }
        if let Some(end) = chunk[..read].iter().position(|&byte| byte == 0) {
            bytes.extend_from_slice(&chunk[..end]);
            return Some(bytes);
        }
        bytes.extend_from_slice(&chunk[..read]);
        cursor += read as u64;
    }
    None
}

/// A copy of a descriptor of the tracee, which needs Linux 5.6.
pub fn copy_descriptor(pid: Pid, fd: RawFd) -> io::Result<OwnedFd> {
    let pidfd = match process_descriptor(pid) {
        Err(error) if error.raw_os_error() == Some(libc::EINVAL) => {
            process_descriptor(thread_group(pid).ok_or(error)?)?
        }
        pidfd => pidfd?,
    };
    // SAFETY: pidfd_getfd returns a new close-on-exec descriptor or -1.
    let copy = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd.as_raw_fd(), fd, 0) };
    if copy < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: as above.
    Ok(unsafe { OwnedFd::from_raw_fd(copy as RawFd) })
}

pub fn process_descriptor(pid: Pid) -> io::Result<OwnedFd> {
    // SAFETY: pidfd_open returns a new descriptor or -1.
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid.as_raw(), 0) };
    if pidfd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the descriptor was just created and is owned here.
    Ok(unsafe { OwnedFd::from_raw_fd(pidfd as RawFd) })
}

/// The process a thread belongs to. A pidfd names a process unless it is
/// opened with PIDFD_THREAD, which came in Linux 6.9.
fn thread_group(tid: Pid) -> Option<Pid> {
    let status = fs::read_to_string(format!("/proc/{tid}/status")).ok()?;
    let tgid = status.lines().find_map(|line| line.strip_prefix("Tgid:"))?;
    tgid.trim().parse().ok().map(Pid::from_raw)
}

pub fn fd_path(pid: Pid, fd: i32) -> Option<PathBuf> {
    let link = fs::read_link(format!("/proc/{pid}/fd/{fd}")).ok()?;
    link.is_absolute().then_some(link)
}

pub fn working_directory(pid: Pid) -> Option<PathBuf> {
    fs::read_link(format!("/proc/{pid}/cwd")).ok()
}

/// The path a call names: `raw` as the tracee wrote it, after the directory
/// it is relative to.
pub fn resolve_at(directories: &WorkingDirectories, pid: Pid, dirfd: i32, raw: &[u8]) -> Option<PathBuf> {
    let raw = Path::new(OsStr::from_bytes(raw));
    let joined = if raw.is_absolute() {
        raw.to_path_buf()
    } else if dirfd == libc::AT_FDCWD {
        directories.of(pid)?.join(raw)
    } else {
        fd_path(pid, dirfd)?.join(raw)
    };
    Some(as_seen_by(pid, without_redundant_components(joined)))
}

pub fn path_at(directories: &WorkingDirectories, pid: Pid, dirfd: i32, address: u64) -> Option<PathBuf> {
    resolve_at(directories, pid, dirfd, &read_c_string(pid, address)?)
}

/// The path a call names, or the file its descriptor refers to when the call
/// asks for that with an empty path.
pub fn path_or_descriptor(
    directories: &WorkingDirectories,
    pid: Pid,
    dirfd: i32,
    address: u64,
    flags: u64,
) -> Option<PathBuf> {
    let raw = read_c_string(pid, address)?;
    if raw.is_empty() && flags & libc::AT_EMPTY_PATH as u64 != 0 {
        fd_path(pid, dirfd)
    } else {
        resolve_at(directories, pid, dirfd, &raw)
    }
}

fn without_redundant_components(path: PathBuf) -> PathBuf {
    let names = path.as_os_str().as_bytes().get(1..).unwrap_or_default();
    let is_redundant = |name: &[u8]| name.is_empty() || name == b".";
    if names.is_empty() || !names.split(|&byte| byte == b'/').any(is_redundant) {
        return path;
    }
    path.components().filter(|component| *component != Component::CurDir).collect()
}

/// `/proc/self` means the tracee, not xcache, when the tracee says it.
fn as_seen_by(pid: Pid, path: PathBuf) -> PathBuf {
    let path = through_link_to_proc_self(path);
    if !path.as_os_str().as_bytes().starts_with(b"/proc/") {
        return path;
    }
    for (alias, target) in
        [("/proc/thread-self", format!("/proc/{pid}/task/{pid}")), ("/proc/self", format!("/proc/{pid}"))]
    {
        if let Ok(rest) = path.strip_prefix(alias) {
            return Path::new(&target).join(rest);
        }
    }
    path
}

/// `/dev/fd`, `/dev/stdin`, `/dev/stdout` and `/dev/stderr` are symlinks into
/// `/proc/self`, which xcache would follow into its own descriptors.
fn through_link_to_proc_self(path: PathBuf) -> PathBuf {
    if !path.as_os_str().as_bytes().starts_with(b"/dev/") {
        return path;
    }
    for link in ["/dev/fd", "/dev/stdin", "/dev/stdout", "/dev/stderr"] {
        if let Ok(rest) = path.strip_prefix(link)
            && let Ok(target) = fs::read_link(link)
            && target.starts_with("/proc/self")
        {
            return target.components().chain(rest.components()).collect();
        }
    }
    path
}

/// Files mapped into a freshly executed image: the executable itself and the
/// ELF interpreter, which the kernel loads without any traced system call.
pub fn mapped_files(pid: Pid) -> Vec<PathBuf> {
    let Ok(maps) = fs::read(format!("/proc/{pid}/maps")) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = maps
        .split(|&byte| byte == b'\n')
        .filter_map(|line| {
            let start = line.iter().position(|&byte| byte == b'/')?;
            let path = &line[start..];
            (!path.ends_with(b" (deleted)")).then(|| PathBuf::from(OsStr::from_bytes(path)))
        })
        .collect();
    files.sort();
    files.dedup();
    files
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_directory_components_are_dropped_but_parents_kept() {
        assert_eq!(without_redundant_components("/a/./b//c/../d".into()), PathBuf::from("/a/b/c/../d"));
        assert_eq!(without_redundant_components("/a/b/".into()), PathBuf::from("/a/b"));
        assert_eq!(without_redundant_components("/a/.b/c..".into()), PathBuf::from("/a/.b/c.."));
        assert_eq!(without_redundant_components("/".into()), PathBuf::from("/"));
    }

    #[test]
    fn proc_self_refers_to_the_tracee() {
        let tracee = Pid::from_raw(42);
        assert_eq!(as_seen_by(tracee, "/proc/self/cwd/a".into()), PathBuf::from("/proc/42/cwd/a"));
        assert_eq!(as_seen_by(tracee, "/proc/selfish".into()), PathBuf::from("/proc/selfish"));
        assert_eq!(as_seen_by(tracee, "/dev/fd/3/a".into()), PathBuf::from("/proc/42/fd/3/a"));
        assert_eq!(as_seen_by(tracee, "/dev/stderr".into()), PathBuf::from("/proc/42/fd/2"));
        assert_eq!(as_seen_by(tracee, "/dev/fdx".into()), PathBuf::from("/dev/fdx"));
    }

    #[test]
    fn reads_strings_from_own_memory() {
        let text = c"/some/path";
        let pid = nix::unistd::getpid();
        assert_eq!(read_c_string(pid, text.as_ptr() as u64).unwrap(), b"/some/path");
    }

    #[test]
    fn own_executable_is_mapped() {
        let exe = fs::read_link("/proc/self/exe").unwrap();
        assert!(mapped_files(nix::unistd::getpid()).contains(&exe));
    }
}
