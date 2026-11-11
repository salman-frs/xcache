//! Each test sets a trap for the cache: a change that a naive cache would miss.
//! Tests need sh, gcc, go, python3 and git on PATH.

mod inputs;
mod invocation;
mod network;
mod not_cached;
mod restore;
mod shadow;
mod support;
mod tracing;
