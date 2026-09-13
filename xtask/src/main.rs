//! Workspace build helpers.
//!
//! `build-ebpf` compiles the eBPF object; `package` assembles a release
//! directory (agent + embedded eBPF object, frontend bundle, systemd unit and
//! installer) plus a checksummed tarball. `package` only runs on Linux because
//! it ships the host binary.

use std::{
    env, fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, bail};

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> Result<()> {
    match env::args().nth(1).as_deref() {
        Some("build-ebpf") => build_ebpf(),
        Some("package") => package(env::args().skip(2).collect()),
        _ => {
            eprintln!(
                "usage: cargo xtask build-ebpf\n       \
                 cargo xtask package [--out <dir>]"
            );
            std::process::exit(2);
        }
    }
}

fn build_ebpf() -> Result<()> {
    let root = workspace_root()?;
    let mut command = Command::new("cargo");
    command.current_dir(&root).args([
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
        "-Z",
        "build-std-features=compiler-builtins-mem",
        "--features",
        "bpf",
    ]);
    command.env(
        "CARGO_ENCODED_RUSTFLAGS",
        ["-Cdebuginfo=2", "-Clink-arg=--btf"].join("\u{1f}"),
    );

    let status = command
        .status()
        .context("run cargo build for the eBPF object")?;

    if !status.success() {
        bail!("eBPF build failed with {status}");
    }

    // The object is embedded into the agent, so DWARF would ride along unused.
    // Keep .BTF (aya needs it for map/spin-lock definitions) and drop the rest.
    let object = root.join("target/bpfel-unknown-none/release/zimascope-ebpf");
    let stripped = ["llvm-objcopy", "objcopy"].iter().find_map(|tool| {
        Command::new(tool)
            .arg("--strip-debug")
            .arg(&object)
            .status()
            .ok()
            .filter(|status| status.success())
            .map(|_| *tool)
    });
    match stripped {
        Some(tool) => println!("eBPF object stripped with {tool}"),
        None => println!("eBPF object kept unstripped: no objcopy on PATH"),
    }

    println!("eBPF object ready at target/bpfel-unknown-none/release/zimascope-ebpf");
    Ok(())
}

fn package(args: Vec<String>) -> Result<()> {
    if env::consts::OS != "linux" {
        bail!("cargo xtask package ships the host binary and only runs on Linux");
    }

    let mut out_dir = PathBuf::from("target/release-pack");
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--out" => {
                out_dir = PathBuf::from(args.next().context("--out needs a directory")?);
            }
            other => bail!("unknown package argument {other:?}"),
        }
    }

    let root = workspace_root()?;
    build_ebpf()?;

    // The frontend must be built before the agent: build.rs embeds the dist
    // bundle into the binary, so a later build would carry a stale bundle.
    let web = build_frontend(&root)?;
    if !web.join("index.html").is_file() {
        bail!("frontend build did not produce index.html");
    }

    println!("building the release agent (embedded eBPF object and frontend)");
    let status = Command::new("cargo")
        .current_dir(&root)
        .args(["build", "--release", "--package", "zimascoped"])
        .status()
        .context("run cargo build for the agent")?;
    if !status.success() {
        bail!("agent build failed with {status}");
    }

    let name = format!(
        "zimascope-{VERSION}-{}-linux",
        match env::consts::ARCH {
            "x86_64" => "x86_64",
            "aarch64" => "aarch64",
            other => other,
        }
    );
    let out_dir = if out_dir.is_absolute() {
        out_dir
    } else {
        root.join(out_dir)
    };
    let release_dir = out_dir.join(&name);
    if release_dir.exists() {
        fs::remove_dir_all(&release_dir).context("clear previous release directory")?;
    }
    fs::create_dir_all(release_dir.join("bin")).context("create release bin/")?;

    let agent = root.join("target/release/zimascoped");
    fs::copy(&agent, release_dir.join("bin/zimascoped"))
        .with_context(|| format!("copy {}", agent.display()))?;
    for (file, mode) in [("zimascoped.service", 0o644), ("install.sh", 0o755)] {
        let source = root.join("packaging").join(file);
        let target = release_dir.join(file);
        fs::copy(&source, &target).with_context(|| format!("copy {}", source.display()))?;
        fs::set_permissions(&target, fs::Permissions::from_mode(mode))
            .with_context(|| format!("chmod {file}"))?;
    }

    write_checksums(&release_dir)?;

    let tarball = out_dir.join(format!("{name}.tar.gz"));
    let status = Command::new("tar")
        .current_dir(&out_dir)
        .arg("-czf")
        .arg(&tarball)
        .arg(&name)
        .status()
        .context("create release tarball")?;
    if !status.success() {
        bail!("tar failed with {status}");
    }

    println!("release ready: {}", tarball.display());
    Ok(())
}

fn build_frontend(root: &Path) -> Result<PathBuf> {
    let frontend = root.join("frontend");
    if !frontend.join("node_modules").is_dir() {
        println!("frontend/node_modules is missing; running npm ci");
        let status = Command::new("npm")
            .current_dir(&frontend)
            .args(["ci"])
            .status()
            .context("run npm ci")?;
        if !status.success() {
            bail!("npm ci failed with {status}");
        }
    }

    println!("building the frontend");
    let status = Command::new("npm")
        .current_dir(&frontend)
        .args(["run", "build"])
        .status()
        .context("run npm run build")?;
    if !status.success() {
        bail!("frontend build failed with {status}");
    }

    Ok(frontend.join("dist"))
}

fn write_checksums(release_dir: &Path) -> Result<()> {
    let mut entries = Vec::new();
    collect_files(release_dir, release_dir, &mut entries)?;
    entries.sort();
    let mut listing = String::new();
    for relative in entries {
        let output = Command::new("sha256sum")
            .current_dir(release_dir)
            .arg(&relative)
            .output()
            .with_context(|| format!("sha256sum {relative}"))?;
        if !output.status.success() {
            bail!("sha256sum failed for {relative}");
        }
        listing.push_str(&String::from_utf8_lossy(&output.stdout));
    }
    fs::write(release_dir.join("SHA256SUMS"), listing).context("write SHA256SUMS")?;
    Ok(())
}

fn collect_files(root: &Path, directory: &Path, files: &mut Vec<String>) -> Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            collect_files(root, &entry.path(), files)?;
        } else {
            let relative = entry
                .path()
                .strip_prefix(root)
                .expect("release entry under root")
                .to_string_lossy()
                .into_owned();
            files.push(relative);
        }
    }
    Ok(())
}

fn workspace_root() -> Result<PathBuf> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .map(PathBuf::from)
        .context("xtask has no workspace root")
}
