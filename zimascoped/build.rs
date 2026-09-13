use std::{
    env, fs,
    path::{Path, PathBuf},
};

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

    write_embedded_ui(&manifest_dir, &out_dir);
}

/// Generates `embedded_ui.rs` from the built frontend when it is present, so
/// a release binary serves the SPA without a `web/` directory next to it.
///
/// A checkout that never ran `npm run build` still compiles: the bundle is
/// empty and the agent serves the API only.
fn write_embedded_ui(manifest_dir: &Path, out_dir: &Path) {
    let dist = manifest_dir
        .parent()
        .expect("agent crate has a workspace root")
        .join("frontend")
        .join("dist");
    println!("cargo:rerun-if-changed={}", dist.display());

    let mut files: Vec<(String, PathBuf)> = Vec::new();
    collect_files(&dist, &dist, &mut files);
    files.sort();

    let mut source = String::from("// Generated from frontend/dist by build.rs.\n");
    if files.is_empty() {
        source.push_str("pub static UI_INDEX: &[u8] = &[];\n");
        source.push_str("pub static UI_ASSETS: &[(&str, &[u8])] = &[];\n");
    } else {
        for (index, (_, path)) in files.iter().enumerate() {
            println!("cargo:rerun-if-changed={}", path.display());
            source.push_str(&format!(
                "static BUNDLED_{index}: &[u8] = include_bytes!({:?});\n",
                path.to_string_lossy()
            ));
        }
        let index_position = files
            .iter()
            .position(|(relative, _)| relative == "index.html")
            .expect("frontend build always emits index.html");
        source.push_str(&format!(
            "pub static UI_INDEX: &[u8] = BUNDLED_{index_position};\n"
        ));
        source.push_str("pub static UI_ASSETS: &[(&str, &[u8])] = &[\n");
        for (index, (relative, _)) in files.iter().enumerate() {
            if relative == "index.html" {
                continue;
            }
            source.push_str(&format!("    ({relative:?}, BUNDLED_{index}),\n"));
        }
        source.push_str("];\n");
    }
    fs::write(out_dir.join("embedded_ui.rs"), source).expect("write generated frontend assets");
}

fn collect_files(root: &Path, directory: &Path, files: &mut Vec<(String, PathBuf)>) {
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        let path = entry.path();
        if file_type.is_dir() {
            collect_files(root, &path, files);
        } else if file_type.is_file() {
            if let Ok(relative) = path.strip_prefix(root) {
                files.push((relative.to_string_lossy().replace('\\', "/"), path));
            }
        }
    }
}
