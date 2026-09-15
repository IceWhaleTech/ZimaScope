//! Shared types for Z-Scope.
//!
//! [`kernel_abi`] contains the fixed-size, `#[repr(C)]` types shared with the
//! eBPF programs and is `no_std`-compatible. [`model`] contains the user-space
//! domain values and requires the `std` feature.

#![cfg_attr(not(feature = "std"), no_std)]

pub mod kernel_abi;

#[cfg(feature = "std")]
pub mod model;
