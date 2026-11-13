use libc::{c_long, sock_filter, sock_fprog};

use super::syscalls::Rule;

const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_TRACE: u32 = 0x7ff0_0000;
const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
pub const FOREIGN_ABI: u32 = 1;

const ARCH_OFFSET: u32 = 4;
const NR_OFFSET: u32 = 0;
const ARGS_OFFSET: u32 = 16;
const LD_W_ABS: u16 = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
const JEQ_K: u16 = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
const JSET_K: u16 = (libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K) as u16;
const RET_K: u16 = (libc::BPF_RET | libc::BPF_K) as u16;

#[cfg(target_arch = "x86_64")]
pub const NATIVE_AUDIT_ARCH: u32 = 0xc000_003e;
#[cfg(target_arch = "aarch64")]
pub const NATIVE_AUDIT_ARCH: u32 = 0xc000_00b7;

#[cfg(target_arch = "x86_64")]
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

/// Who sees the calls that only need to be observed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Observer {
    Tracer,
    Supervisor,
}

pub struct Filter {
    instructions: Vec<sock_filter>,
}

impl Filter {
    pub fn new(rules: &[(c_long, Rule)], observer: Observer) -> Self {
        let observe = match observer {
            Observer::Tracer => SECCOMP_RET_TRACE,
            Observer::Supervisor => SECCOMP_RET_USER_NOTIF,
        };
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
        for &(nr, rule) in rules {
            let body = match rule {
                Rule::Trace => vec![ret(SECCOMP_RET_TRACE)],
                Rule::Observe => vec![ret(observe)],
                Rule::ObserveReading { flags, writing } => vec![
                    load(ARGS_OFFSET + 8 * flags as u32),
                    sock_filter { code: JSET_K, jt: 0, jf: 1, k: writing },
                    ret(SECCOMP_RET_TRACE),
                    ret(observe),
                ],
                Rule::TraceFlagged { flags, noted } => vec![
                    load(ARGS_OFFSET + 8 * flags as u32),
                    sock_filter { code: JSET_K, jt: 0, jf: 1, k: noted },
                    ret(SECCOMP_RET_TRACE),
                    ret(SECCOMP_RET_ALLOW),
                ],
                Rule::Refuse => vec![ret(SECCOMP_RET_ERRNO | libc::ENOSYS as u32)],
            };
            instructions.push(jump_if_equal(nr as u32, 0, body.len() as u8));
            instructions.extend(body);
        }
        instructions.push(ret(SECCOMP_RET_ALLOW));
        Self { instructions }
    }

    pub fn program(&self) -> sock_fprog {
        sock_fprog { len: self.instructions.len() as u16, filter: self.instructions.as_ptr().cast_mut() }
    }
}

/// Loads a 32-bit word of `seccomp_data`; for an argument, its low half on
/// these little-endian targets.
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
    use crate::trace::syscalls;

    #[test]
    fn program_fits_the_kernel_limit() {
        for observer in [Observer::Tracer, Observer::Supervisor] {
            let filter = Filter::new(&syscalls::rules(), observer);
            assert!(filter.program().len < 4096);
            assert_eq!(filter.instructions.last().unwrap().k, SECCOMP_RET_ALLOW);
        }
    }
}
