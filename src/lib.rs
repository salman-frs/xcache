#[cfg(not(target_os = "linux"))]
compile_error!("xcache traces Linux system calls and only builds for Linux");

pub mod cli;
mod digest;
mod git;
mod invocation;
mod observe;
mod outputs;
mod path_serde;
mod record;
mod run;
mod stdio;
mod store;
mod sync;
mod trace;
