use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use ulid::Ulid;

use crate::bpf_compiler::{self, EbpfCompiler};

pub const ZEROSERVE_H: &[u8] = include_bytes!("../sdk/zeroserve.h");
pub const ZEROSERVE_CADDY_H: &[u8] = include_bytes!("../sdk/zeroserve_caddy.h");

pub struct WorkDir {
    path: PathBuf,
}

impl WorkDir {
    pub fn new(prefix: &str) -> Result<Self> {
        let path = std::env::temp_dir().join(format!("{prefix}-{}", Ulid::new()));
        fs::create_dir_all(&path)
            .with_context(|| format!("failed to create temp dir {}", path.display()))?;
        write_sdk_headers(&path)?;
        Ok(Self { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for WorkDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

pub fn compile_c_path_to_object_bytes(source: &Path, compiler: EbpfCompiler) -> Result<Vec<u8>> {
    let work_dir = WorkDir::new("zeroserve-script")?;
    let stem = source
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("script");
    let obj_path = work_dir.path().join(format!("{stem}-{}.o", Ulid::new()));
    bpf_compiler::compile_file_to_object(compiler, source, work_dir.path(), &obj_path)?;
    let object = fs::read(&obj_path)
        .with_context(|| format!("failed to read compiled object {}", obj_path.display()))?;
    if object.is_empty() {
        bail!("compiled object for {} is empty", source.display());
    }
    Ok(object)
}

fn write_sdk_headers(dir: &Path) -> Result<()> {
    fs::write(dir.join("zeroserve.h"), ZEROSERVE_H)
        .with_context(|| format!("failed to write headers into {}", dir.display()))?;
    fs::write(dir.join("zeroserve_caddy.h"), ZEROSERVE_CADDY_H)
        .with_context(|| format!("failed to write headers into {}", dir.display()))?;
    Ok(())
}
