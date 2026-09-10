use std::{env, fs, path::PathBuf};

fn main() {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set by cargo"));
    println!("cargo:rerun-if-env-changed=ZIMASCOPE_EBPF_OBJECT");

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let object = env::var_os("ZIMASCOPE_EBPF_OBJECT")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from("..")
                .join("target")
                .join("bpfel-unknown-none")
                .join("release")
                .join("zimascope-ebpf")
        });

    let contents = if target_os == "linux" && object.is_file() {
        println!("cargo:rerun-if-changed={}", object.display());
        format!(
            "pub static EBPF_OBJECT: &[u8] = aya::include_bytes_aligned!({:?});\n",
            object.display().to_string()
        )
    } else {
        "pub static EBPF_OBJECT: &[u8] = &[];\n".to_string()
    };

    fs::write(out_dir.join("ebpf_object.rs"), contents).expect("write generated eBPF object");
}
