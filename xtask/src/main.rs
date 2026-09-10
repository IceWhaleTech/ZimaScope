use std::{env, path::PathBuf, process::Command};

use anyhow::{Context, Result, bail};

fn main() -> Result<()> {
    match env::args().nth(1).as_deref() {
        Some("build-ebpf") => build_ebpf(),
        _ => {
            eprintln!("usage: cargo xtask build-ebpf");
            std::process::exit(2);
        }
    }
}

fn build_ebpf() -> Result<()> {
    let root = workspace_root()?;
    let status = Command::new("cargo")
        .current_dir(&root)
        .args([
            "+nightly",
            "build",
            "--package",
            "zimascope-ebpf",
            "--bin",
            "zimascope-ebpf",
            "--release",
            "--target",
            "bpfel-unknown-none",
            "-Z",
            "build-std=core",
            "--features",
            "bpf",
        ])
        .status()
        .context("run cargo build for the eBPF object")?;

    if !status.success() {
        bail!("eBPF build failed with {status}");
    }

    println!("eBPF object ready at target/bpfel-unknown-none/release/zimascope-ebpf");
    Ok(())
}

fn workspace_root() -> Result<PathBuf> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .map(PathBuf::from)
        .context("xtask has no workspace root")
}
