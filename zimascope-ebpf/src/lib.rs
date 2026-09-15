//! Host-testable parts of the Z-Scope eBPF crate.
//!
//! The TC programs live in `src/main.rs` and are only built for the `bpf`
//! target; the bounded parser is ordinary `no_std` code that runs in the eBPF
//! program and in host unit tests.

#![no_std]

pub mod domain;
pub mod parse;
