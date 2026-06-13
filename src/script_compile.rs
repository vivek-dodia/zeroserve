use std::{
    ffi::{OsStr, OsString},
    fs::{self, File},
    io::{Read, Seek, SeekFrom, Write},
    os::fd::AsRawFd,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use anyhow::{Context, Result, bail};
use nix::sys::memfd::{MFdFlags, memfd_create};
use ulid::Ulid;

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

pub struct CompiledObject {
    pub obj_path: PathBuf,
    bc_path: PathBuf,
}

impl Drop for CompiledObject {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.obj_path);
        let _ = fs::remove_file(&self.bc_path);
    }
}

pub fn compile_c_path_to_temp_object(source: &Path, work_dir: &WorkDir) -> Result<CompiledObject> {
    let stem = source
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("script");
    let unique = Ulid::new();
    let bc_path = work_dir.path().join(format!("{stem}-{unique}.bc"));
    let obj_path = work_dir.path().join(format!("{stem}-{unique}.o"));

    run_clang(
        source.as_os_str(),
        bc_path.as_os_str(),
        work_dir.path(),
        &source.display().to_string(),
        false,
    )?;
    run_llc(
        bc_path.as_os_str(),
        obj_path.as_os_str(),
        &source.display().to_string(),
    )?;

    Ok(CompiledObject { obj_path, bc_path })
}

pub fn compile_c_path_to_object_bytes(source: &Path) -> Result<Vec<u8>> {
    let work_dir = WorkDir::new("zeroserve-script")?;
    let compiled = compile_c_path_to_temp_object(source, &work_dir)?;
    let object = fs::read(&compiled.obj_path).with_context(|| {
        format!(
            "failed to read compiled object {}",
            compiled.obj_path.display()
        )
    })?;
    if object.is_empty() {
        bail!("compiled object for {} is empty", source.display());
    }
    Ok(object)
}

pub fn compile_c_source_to_object_bytes(name: &str, c_source: &str) -> Result<Vec<u8>> {
    let mut c_memfd = make_memfd(name)?;
    c_memfd
        .write_all(c_source.as_bytes())
        .context("failed to write generated C into memfd")?;
    c_memfd.flush().ok();

    let bc_memfd = make_memfd("zeroserve-script.bc")?;
    let mut o_memfd = make_memfd("zeroserve-script.o")?;
    let work_dir = WorkDir::new("zeroserve-c-compile")?;

    let source = fd_path(&c_memfd);
    let bitcode = fd_path(&bc_memfd);
    let object = fd_path(&o_memfd);
    run_clang(&source, &bitcode, work_dir.path(), name, true)?;
    run_llc(&bitcode, &object, name)?;

    // clang/llc wrote through a separate open file description; rewind our own
    // handle before reading the produced object back out.
    o_memfd
        .seek(SeekFrom::Start(0))
        .context("failed to rewind object memfd")?;
    let mut object = Vec::new();
    o_memfd
        .read_to_end(&mut object)
        .context("failed to read compiled object from memfd")?;
    if object.is_empty() {
        bail!("compiled object for {name} is empty");
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

fn run_clang(
    source: &OsStr,
    bitcode: &OsStr,
    header_dir: &Path,
    label: &str,
    force_c: bool,
) -> Result<()> {
    let mut command = Command::new("clang");
    command.args([
        "-O2",
        "-Wall",
        "-target",
        "bpf",
        "-fno-builtin",
        "-emit-llvm",
    ]);
    if force_c {
        command.args(["-x", "c"]);
    }
    let status = command
        .arg("-c")
        .arg("-I")
        .arg(header_dir)
        .arg(source)
        .arg("-o")
        .arg(bitcode)
        .stdout(Stdio::null())
        .status()
        .with_context(|| format!("failed to run clang on {label}"))?;
    if !status.success() {
        bail!("clang failed for {label}");
    }
    Ok(())
}

fn run_llc(bitcode: &OsStr, object: &OsStr, label: &str) -> Result<()> {
    let status = Command::new("llc")
        .args([
            "-march=bpf",
            "-bpf-stack-size=4096",
            "-mcpu=v3",
            "-filetype=obj",
        ])
        .arg(bitcode)
        .arg("-o")
        .arg(object)
        .stdout(Stdio::null())
        .status()
        .with_context(|| format!("failed to run llc on {label}"))?;
    if !status.success() {
        bail!("llc failed for {label}");
    }
    Ok(())
}

/// Create an anonymous in-memory file. The fd is left inheritable (no
/// `MFD_CLOEXEC`) so clang/llc child processes can reach it through
/// `/proc/self/fd/<fd>`.
fn make_memfd(name: &str) -> Result<File> {
    let cname = std::ffi::CString::new(name).expect("memfd name has no interior NUL");
    let fd = memfd_create(cname.as_c_str(), MFdFlags::empty())
        .with_context(|| format!("memfd_create({name}) failed"))?;
    Ok(File::from(fd))
}

fn fd_path(file: &File) -> OsString {
    OsString::from(format!("/proc/self/fd/{}", file.as_raw_fd()))
}
