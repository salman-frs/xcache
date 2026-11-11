use libc::c_long;

use crate::observe::Access;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Call {
    Open { dirfd: i32, path: u64, flags: u64 },
    OpenHow { dirfd: i32, path: u64, how: u64 },
    Exec { dirfd: i32, path: u64, flags: u64 },
    Probe { dirfd: i32, path: u64, flags: u64, access: Access },
    List { fd: i32 },
    Unlink { dirfd: i32, path: u64, flags: u64 },
    Rename { old_dirfd: i32, old: u64, new_dirfd: i32, new: u64, flags: u64 },
    MakeNode { dirfd: i32, path: u64 },
    Link { old_dirfd: i32, old: u64, new_dirfd: i32, new: u64, flags: u64 },
    Symlink { new_dirfd: i32, new: u64 },
    Chmod { dirfd: i32, path: u64 },
    ChmodFd { fd: i32 },
    SetTimes { dirfd: i32, path: u64, flags: u64, times: u64, timespecs: bool },
    Truncate { path: u64, length: u64 },
    Connect { fd: i32, addr: u64, len: u64 },
    SendTo { addr: u64, len: u64 },
    SendMsg { msg: u64 },
    SendMmsg { msgs: u64, count: u64 },
    Clone { flags: u64 },
    Clone3 { args: u64 },
    Unshare { flags: u64 },
    Accept,
    Bind { addr: u64, len: u64 },
    Unsupported(&'static str),
}

const AT_FDCWD: i32 = libc::AT_FDCWD;
pub const FCHMODAT2: c_long = 452;

pub fn decode(nr: u64, args: [u64; 6]) -> Option<Call> {
    let fd = |index: usize| args[index] as i32;
    let [a0, a1, a2, a3, a4, _] = args;
    let call = match nr as c_long {
        libc::SYS_openat => Call::Open { dirfd: fd(0), path: a1, flags: a2 },
        libc::SYS_openat2 => Call::OpenHow { dirfd: fd(0), path: a1, how: a2 },
        libc::SYS_execve => Call::Exec { dirfd: AT_FDCWD, path: a0, flags: 0 },
        libc::SYS_execveat => Call::Exec { dirfd: fd(0), path: a1, flags: a4 },
        libc::SYS_newfstatat => Call::Probe { dirfd: fd(0), path: a1, flags: a3, access: Access::Stat },
        libc::SYS_statx => Call::Probe { dirfd: fd(0), path: a1, flags: a2, access: Access::Stat },
        libc::SYS_faccessat => Call::Probe { dirfd: fd(0), path: a1, flags: 0, access: Access::Stat },
        libc::SYS_faccessat2 => Call::Probe { dirfd: fd(0), path: a1, flags: a3, access: Access::Stat },
        libc::SYS_readlinkat => Call::Probe { dirfd: fd(0), path: a1, flags: 0, access: Access::Lstat },
        libc::SYS_chdir => Call::Probe { dirfd: AT_FDCWD, path: a0, flags: 0, access: Access::Stat },
        libc::SYS_getdents64 => Call::List { fd: fd(0) },
        libc::SYS_unlinkat => Call::Unlink { dirfd: fd(0), path: a1, flags: a2 },
        libc::SYS_renameat => Call::Rename { old_dirfd: fd(0), old: a1, new_dirfd: fd(2), new: a3, flags: 0 },
        libc::SYS_renameat2 => Call::Rename { old_dirfd: fd(0), old: a1, new_dirfd: fd(2), new: a3, flags: a4 },
        libc::SYS_mkdirat | libc::SYS_mknodat => Call::MakeNode { dirfd: fd(0), path: a1 },
        libc::SYS_linkat => Call::Link { old_dirfd: fd(0), old: a1, new_dirfd: fd(2), new: a3, flags: a4 },
        libc::SYS_symlinkat => Call::Symlink { new_dirfd: fd(1), new: a2 },
        libc::SYS_fchmodat | FCHMODAT2 => Call::Chmod { dirfd: fd(0), path: a1 },
        libc::SYS_fchmod => Call::ChmodFd { fd: fd(0) },
        libc::SYS_utimensat => Call::SetTimes { dirfd: fd(0), path: a1, flags: a3, times: a2, timespecs: true },
        libc::SYS_truncate => Call::Truncate { path: a0, length: a1 },
        libc::SYS_connect => Call::Connect { fd: fd(0), addr: a1, len: a2 },
        libc::SYS_sendto => Call::SendTo { addr: a4, len: args[5] },
        libc::SYS_sendmsg => Call::SendMsg { msg: a1 },
        libc::SYS_sendmmsg => Call::SendMmsg { msgs: a1, count: a2 },
        libc::SYS_clone => Call::Clone { flags: a0 },
        libc::SYS_clone3 => Call::Clone3 { args: a0 },
        libc::SYS_unshare => Call::Unshare { flags: a0 },
        libc::SYS_setns => Call::Unsupported("joins another Linux namespace"),
        libc::SYS_accept | libc::SYS_accept4 => Call::Accept,
        libc::SYS_bind => Call::Bind { addr: a1, len: a2 },
        libc::SYS_mount
        | libc::SYS_umount2
        | libc::SYS_pivot_root
        | libc::SYS_open_tree
        | libc::SYS_move_mount
        | libc::SYS_fsopen
        | libc::SYS_fsconfig
        | libc::SYS_fsmount
        | libc::SYS_fspick
        | libc::SYS_mount_setattr => Call::Unsupported("changes mounts"),
        libc::SYS_chroot => Call::Unsupported("changes its root directory"),
        libc::SYS_open_by_handle_at => Call::Unsupported("opens files by handle"),
        #[cfg(target_arch = "x86_64")]
        nr => return decode_legacy(nr, args),
        #[cfg(not(target_arch = "x86_64"))]
        _ => return None,
    };
    Some(call)
}

#[cfg(target_arch = "x86_64")]
fn decode_legacy(nr: c_long, args: [u64; 6]) -> Option<Call> {
    const O_CREAT_WRONLY_TRUNC: u64 = (libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC) as u64;
    let [a0, a1, ..] = args;
    let call = match nr {
        libc::SYS_open => Call::Open { dirfd: AT_FDCWD, path: a0, flags: a1 },
        libc::SYS_creat => Call::Open { dirfd: AT_FDCWD, path: a0, flags: O_CREAT_WRONLY_TRUNC },
        libc::SYS_stat | libc::SYS_access => Call::Probe { dirfd: AT_FDCWD, path: a0, flags: 0, access: Access::Stat },
        libc::SYS_lstat | libc::SYS_readlink => {
            Call::Probe { dirfd: AT_FDCWD, path: a0, flags: 0, access: Access::Lstat }
        }
        libc::SYS_getdents => Call::List { fd: a0 as i32 },
        libc::SYS_unlink => Call::Unlink { dirfd: AT_FDCWD, path: a0, flags: 0 },
        libc::SYS_rmdir => Call::Unlink { dirfd: AT_FDCWD, path: a0, flags: libc::AT_REMOVEDIR as u64 },
        libc::SYS_rename => Call::Rename { old_dirfd: AT_FDCWD, old: a0, new_dirfd: AT_FDCWD, new: a1, flags: 0 },
        libc::SYS_mkdir | libc::SYS_mknod => Call::MakeNode { dirfd: AT_FDCWD, path: a0 },
        libc::SYS_link => Call::Link { old_dirfd: AT_FDCWD, old: a0, new_dirfd: AT_FDCWD, new: a1, flags: 0 },
        libc::SYS_symlink => Call::Symlink { new_dirfd: AT_FDCWD, new: a1 },
        libc::SYS_chmod => Call::Chmod { dirfd: AT_FDCWD, path: a0 },
        libc::SYS_utime | libc::SYS_utimes => {
            Call::SetTimes { dirfd: AT_FDCWD, path: a0, flags: 0, times: a1, timespecs: false }
        }
        libc::SYS_futimesat => {
            Call::SetTimes { dirfd: a0 as i32, path: a1, flags: 0, times: args[2], timespecs: false }
        }
        _ => return None,
    };
    Some(call)
}

pub fn traced() -> Vec<c_long> {
    let common = [
        libc::SYS_openat,
        libc::SYS_openat2,
        libc::SYS_execve,
        libc::SYS_execveat,
        libc::SYS_newfstatat,
        libc::SYS_statx,
        libc::SYS_faccessat,
        libc::SYS_faccessat2,
        libc::SYS_readlinkat,
        libc::SYS_chdir,
        libc::SYS_getdents64,
        libc::SYS_unlinkat,
        libc::SYS_renameat,
        libc::SYS_renameat2,
        libc::SYS_mkdirat,
        libc::SYS_mknodat,
        libc::SYS_linkat,
        libc::SYS_symlinkat,
        libc::SYS_fchmodat,
        FCHMODAT2,
        libc::SYS_fchmod,
        libc::SYS_utimensat,
        libc::SYS_truncate,
        libc::SYS_connect,
        libc::SYS_sendto,
        libc::SYS_sendmsg,
        libc::SYS_sendmmsg,
        libc::SYS_clone,
        libc::SYS_clone3,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_accept,
        libc::SYS_accept4,
        libc::SYS_bind,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_open_tree,
        libc::SYS_move_mount,
        libc::SYS_fsopen,
        libc::SYS_fsconfig,
        libc::SYS_fsmount,
        libc::SYS_fspick,
        libc::SYS_mount_setattr,
        libc::SYS_pivot_root,
        libc::SYS_chroot,
        libc::SYS_open_by_handle_at,
    ];
    #[cfg(not(target_arch = "x86_64"))]
    let legacy: [c_long; 0] = [];
    #[cfg(target_arch = "x86_64")]
    let legacy = [
        libc::SYS_open,
        libc::SYS_creat,
        libc::SYS_stat,
        libc::SYS_access,
        libc::SYS_lstat,
        libc::SYS_readlink,
        libc::SYS_getdents,
        libc::SYS_unlink,
        libc::SYS_rmdir,
        libc::SYS_rename,
        libc::SYS_mkdir,
        libc::SYS_mknod,
        libc::SYS_link,
        libc::SYS_symlink,
        libc::SYS_chmod,
        libc::SYS_utime,
        libc::SYS_utimes,
        libc::SYS_futimesat,
    ];
    common.into_iter().chain(legacy).collect()
}

/// Calls that bypass per-call tracing entirely; refusing them makes runtimes
/// fall back to ordinary, observable system calls.
pub fn refused() -> Vec<c_long> {
    vec![libc::SYS_io_uring_setup, libc::SYS_io_uring_enter, libc::SYS_io_uring_register]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_traced_call_is_decoded() {
        for nr in traced() {
            assert!(decode(nr as u64, [0; 6]).is_some(), "syscall {nr} is traced but not decoded");
        }
    }

    #[test]
    fn untraced_calls_are_not_decoded() {
        assert_eq!(decode(libc::SYS_read as u64, [0; 6]), None);
        assert_eq!(decode(libc::SYS_write as u64, [0; 6]), None);
    }
}
