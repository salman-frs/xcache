use std::ffi::OsStr;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

use nix::unistd::Pid;

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

pub fn read_memory(pid: Pid, address: u64, buffer: &mut [u8]) -> io::Result<usize> {
    let local = libc::iovec { iov_base: buffer.as_mut_ptr().cast(), iov_len: buffer.len() };
    let remote = libc::iovec { iov_base: address as *mut libc::c_void, iov_len: buffer.len() };
    // SAFETY: both iovecs describe valid ranges; the remote one is only read.
    let read = unsafe { libc::process_vm_readv(pid.as_raw(), &local, 1, &remote, 1, 0) };
    if read < 0 { Err(io::Error::last_os_error()) } else { Ok(read as usize) }
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
    while bytes.len() < PATH_MAX {
        let until_page_end = (PAGE - cursor % PAGE) as usize;
        let mut chunk = vec![0; until_page_end.min(PATH_MAX - bytes.len())];
        let read = read_memory(pid, cursor, &mut chunk).ok()?;
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

pub fn fd_path(pid: Pid, fd: i32) -> Option<PathBuf> {
    let link = fs::read_link(format!("/proc/{pid}/fd/{fd}")).ok()?;
    link.is_absolute().then_some(link)
}

pub fn resolve(pid: Pid, dirfd: i32, raw: &[u8]) -> Option<PathBuf> {
    let raw = Path::new(OsStr::from_bytes(raw));
    let joined = if raw.is_absolute() {
        raw.to_path_buf()
    } else if dirfd == libc::AT_FDCWD {
        fs::read_link(format!("/proc/{pid}/cwd")).ok()?.join(raw)
    } else {
        fd_path(pid, dirfd)?.join(raw)
    };
    Some(as_seen_by(pid, &without_redundant_components(&joined)))
}

fn without_redundant_components(path: &Path) -> PathBuf {
    path.components().filter(|component| *component != Component::CurDir).collect()
}

/// `/proc/self` means the tracee, not xcache, when the tracee says it.
fn as_seen_by(pid: Pid, path: &Path) -> PathBuf {
    for (alias, target) in
        [("/proc/thread-self", format!("/proc/{pid}/task/{pid}")), ("/proc/self", format!("/proc/{pid}"))]
    {
        if let Ok(rest) = path.strip_prefix(alias) {
            return Path::new(&target).join(rest);
        }
    }
    path.to_path_buf()
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
        assert_eq!(without_redundant_components(Path::new("/a/./b//c/../d")), PathBuf::from("/a/b/c/../d"));
    }

    #[test]
    fn proc_self_refers_to_the_tracee() {
        let tracee = Pid::from_raw(42);
        assert_eq!(as_seen_by(tracee, Path::new("/proc/self/cwd/a")), PathBuf::from("/proc/42/cwd/a"));
        assert_eq!(as_seen_by(tracee, Path::new("/proc/selfish")), PathBuf::from("/proc/selfish"));
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
