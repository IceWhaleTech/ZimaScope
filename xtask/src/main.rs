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
                 cargo xtask package [--web <dist-dir>] [--out <dir>]"
            );
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
            "-Z",
            "build-std-features=compiler-builtins-mem",
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

fn package(args: Vec<String>) -> Result<()> {
    if env::consts::OS != "linux" {
        bail!("cargo xtask package ships the host binary and only runs on Linux");
    }

    let mut web_dir: Option<PathBuf> = None;
    let mut out_dir = PathBuf::from("target/release-pack");
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--web" => {
                web_dir = Some(PathBuf::from(
                    args.next().context("--web needs a directory")?,
                ));
            }
            "--out" => {
                out_dir = PathBuf::from(args.next().context("--out needs a directory")?);
            }
            other => bail!("unknown package argument {other:?}"),
        }
    }

    let root = workspace_root()?;
    build_ebpf()?;

    println!("building the release agent (embedded eBPF object)");
    let status = Command::new("cargo")
        .current_dir(&root)
        .args(["build", "--release", "--package", "zimascope-agent"])
        .status()
        .context("run cargo build for the agent")?;
    if !status.success() {
        bail!("agent build failed with {status}");
    }

    let web = match web_dir {
        Some(dir) => {
            let dir = if dir.is_absolute() {
                dir
            } else {
                root.join(dir)
            };
            if !dir.join("index.html").is_file() {
                bail!("{} does not contain index.html", dir.display());
            }
            dir
        }
        None => build_frontend(&root)?,
    };

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

    let agent = root.join("target/release/zimascope-agent");
    fs::copy(&agent, release_dir.join("bin/zimascope-agent"))
        .with_context(|| format!("copy {}", agent.display()))?;
    copy_tree(&web, &release_dir.join("web"))?;
    for (file, mode) in [("zimascope-agent.service", 0o644), ("install.sh", 0o755)] {
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

fn copy_tree(source: &Path, target: &Path) -> Result<()> {
    fs::create_dir_all(target).with_context(|| format!("create {}", target.display()))?;
    for entry in fs::read_dir(source).with_context(|| format!("read {}", source.display()))? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let next = target.join(entry.file_name());
        if file_type.is_dir() {
            copy_tree(&entry.path(), &next)?;
        } else if file_type.is_file() {
            fs::copy(entry.path(), &next)
                .with_context(|| format!("copy {}", entry.path().display()))?;
        }
    }
    Ok(())
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
