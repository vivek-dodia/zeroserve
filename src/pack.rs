use std::{
    ffi::OsStr,
    fs, io,
    path::{Component, Path},
};

use anyhow::{Context, Result, bail};
use tar::Builder;

pub const USER_MANUAL: &str = include_str!("../docs/user_manual.md");

pub fn pack_site(root: &Path) -> Result<()> {
    let meta = fs::metadata(root)
        .with_context(|| format!("failed to stat pack path {}", root.display()))?;
    if !meta.is_dir() {
        bail!("--pack expects a directory, got {}", root.display());
    }

    let work_dir = crate::script_compile::WorkDir::new("zeroserve-pack")?;
    let stdout = io::stdout();
    let mut builder = Builder::new(stdout.lock());

    pack_dir(&mut builder, root, root, &work_dir)?;
    builder.finish().context("failed to finalize tar stream")?;
    Ok(())
}

fn pack_dir(
    builder: &mut Builder<impl io::Write>,
    root: &Path,
    dir: &Path,
    work_dir: &crate::script_compile::WorkDir,
) -> Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("failed to read {}", dir.display()))? {
        let entry = entry.with_context(|| format!("failed to read entry in {}", dir.display()))?;
        let file_type = entry
            .file_type()
            .with_context(|| format!("failed to stat {}", entry.path().display()))?;
        let path = entry.path();
        let rel = path
            .strip_prefix(root)
            .with_context(|| format!("failed to strip prefix {}", root.display()))?;
        if file_type.is_dir() {
            builder
                .append_dir(rel, &path)
                .with_context(|| format!("failed to append directory {}", rel.display()))?;
            pack_dir(builder, root, &path, work_dir)?;
            continue;
        }
        if !file_type.is_file() {
            continue;
        }

        if is_script_c(rel) {
            let compiled = crate::script_compile::compile_c_path_to_temp_object(&path, work_dir)?;
            let mut tar_path = rel.to_path_buf();
            tar_path.set_extension("o");
            builder
                .append_path_with_name(&compiled.obj_path, &tar_path)
                .with_context(|| format!("failed to append {}", tar_path.display()))?;
            continue;
        }

        if is_script_o(rel) {
            let mut c_path = path.clone();
            c_path.set_extension("c");
            if c_path.exists() {
                continue;
            }
        }

        builder
            .append_path_with_name(&path, rel)
            .with_context(|| format!("failed to append {}", rel.display()))?;
    }

    Ok(())
}

fn is_script_c(rel: &Path) -> bool {
    is_scripts_path(rel) && has_extension(rel, "c")
}

fn is_script_o(rel: &Path) -> bool {
    is_scripts_path(rel) && has_extension(rel, "o")
}

fn is_scripts_path(rel: &Path) -> bool {
    let mut comps = rel.components();
    match (comps.next(), comps.next()) {
        (Some(Component::Normal(first)), Some(Component::Normal(second)))
            if first == OsStr::new(".zeroserve") && second == OsStr::new("scripts") =>
        {
            true
        }
        _ => false,
    }
}

fn has_extension(path: &Path, ext: &str) -> bool {
    path.extension()
        .and_then(|s| s.to_str())
        .map(|s| s.eq_ignore_ascii_case(ext))
        .unwrap_or(false)
}
