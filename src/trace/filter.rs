use libc::{c_long, sock_filter, sock_fprog};

const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_TRACE: u32 = 0x7ff0_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
pub const FOREIGN_ABI: u32 = 1;

const ARCH_OFFSET: u32 = 4;
const NR_OFFSET: u32 = 0;
const LD_W_ABS: u16 = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
const JEQ_K: u16 = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
const RET_K: u16 = (libc::BPF_RET | libc::BPF_K) as u16;

#[cfg(target_arch = "x86_64")]
pub const NATIVE_AUDIT_ARCH: u32 = 0xc000_003e;
#[cfg(target_arch = "aarch64")]
pub const NATIVE_AUDIT_ARCH: u32 = 0xc000_00b7;

#[cfg(target_arch = "x86_64")]
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

pub struct Filter {
    instructions: Vec<sock_filter>,
}

impl Filter {
    pub fn new(traced: &[c_long], refused: &[c_long]) -> Self {
        let mut instructions = vec![
            load(ARCH_OFFSET),
            jump_if_equal(NATIVE_AUDIT_ARCH, 1, 0),
            ret(SECCOMP_RET_TRACE | FOREIGN_ABI),
            load(NR_OFFSET),
        ];
        #[cfg(target_arch = "x86_64")]
        instructions.extend([
            sock_filter {
                code: (libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K) as u16,
                jt: 0,
                jf: 1,
                k: X32_SYSCALL_BIT,
            },
            ret(SECCOMP_RET_TRACE | FOREIGN_ABI),
        ]);
        for &nr in refused {
            instructions.extend([jump_if_equal(nr as u32, 0, 1), ret(SECCOMP_RET_ERRNO | libc::ENOSYS as u32)]);
        }
        for &nr in traced {
            instructions.extend([jump_if_equal(nr as u32, 0, 1), ret(SECCOMP_RET_TRACE)]);
        }
        instructions.push(ret(SECCOMP_RET_ALLOW));
        Self { instructions }
    }

    pub fn program(&self) -> sock_fprog {
        sock_fprog { len: self.instructions.len() as u16, filter: self.instructions.as_ptr().cast_mut() }
    }
}

fn load(offset: u32) -> sock_filter {
    sock_filter { code: LD_W_ABS, jt: 0, jf: 0, k: offset }
}

fn jump_if_equal(value: u32, jt: u8, jf: u8) -> sock_filter {
    sock_filter { code: JEQ_K, jt, jf, k: value }
}

fn ret(action: u32) -> sock_filter {
    sock_filter { code: RET_K, jt: 0, jf: 0, k: action }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn program_fits_the_kernel_limit() {
        let filter = Filter::new(&super::super::syscalls::traced(), &super::super::syscalls::refused());
        assert!(filter.program().len < 4096);
        assert_eq!(filter.instructions.last().unwrap().k, SECCOMP_RET_ALLOW);
    }
}
