use std::{env, fs, path::PathBuf};

fn main() {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set by cargo"));
    let manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set"));
    println!("cargo:rerun-if-env-changed=ZIMASCOPE_EBPF_OBJECT");

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let object = env::var_os("ZIMASCOPE_EBPF_OBJECT")
        .map(PathBuf::from)
        .map(|path| {
            if path.is_absolute() {
                path
            } else {
                manifest_dir.join(path)
            }
        })
        .unwrap_or_else(|| {
            manifest_dir
                .parent()
                .expect("agent crate has a workspace root")
                .join("target")
                .join("bpfel-unknown-none")
                .join("release")
                .join("zimascope-ebpf")
        });

    // The generated file is compiled from OUT_DIR, so the embedded path must
    // be absolute; a relative path would be resolved against OUT_DIR.
    let contents = if target_os == "linux" && object.is_file() {
        println!("cargo:rerun-if-changed={}", object.display());
        format!(
            "pub static EBPF_OBJECT: &[u8] = aya::include_bytes_aligned!({:?});\n",
            object.to_string_lossy()
        )
    } else {
        "pub static EBPF_OBJECT: &[u8] = &[];\n".to_string()
    };

    fs::write(out_dir.join("ebpf_object.rs"), contents).expect("write generated eBPF object");
}
