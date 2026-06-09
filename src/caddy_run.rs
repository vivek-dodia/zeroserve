//! The `--caddy` entry point: take a Caddyfile (or Caddy JSON) and produce an
//! in-memory site tarball ready to be served, running the whole
//! Caddyfile -> Caddy JSON -> middleware C -> eBPF object -> tarball pipeline.
//!
//! The generated middleware C and the resulting tarball never touch disk: the C
//! source and the compiler's `.bc`/`.o` artifacts live in anonymous `memfd`
//! files, and the tarball is assembled in memory. Only the static SDK headers
//! (needed for clang's include path) are materialized in a temporary directory,
//! which is removed before returning.

use std::{
    fs::{self, File},
    io::{Read, Seek, SeekFrom, Write},
    os::fd::{AsRawFd, RawFd},
    path::Path,
    process::{Command, Stdio},
};

use anyhow::{Context, Result, bail};
use nix::sys::memfd::{MFdFlags, memfd_create};
use ulid::Ulid;

use crate::config::StaticConfig;
use crate::pack::{ZEROSERVE_CADDY_H, ZEROSERVE_H};
use crate::site::Site;

/// The name the generated middleware object is given inside the tarball. The
/// runtime loads every `.zeroserve/scripts/*.o` entry as an eBPF program.
const SCRIPT_TAR_PATH: &str = ".zeroserve/scripts/caddy.o";

/// Build an in-memory site tarball from a Caddyfile or Caddy JSON config.
///
/// Returns the raw bytes of a tar archive containing a single compiled
/// middleware object at `.zeroserve/scripts/caddy.o`. Adapter and compiler
/// warnings are printed to stderr.
pub fn build_caddy_tarball(config_path: &Path) -> Result<Vec<u8>> {
    let source = fs::read_to_string(config_path)
        .with_context(|| format!("failed to read {}", config_path.display()))?;

    // Auto-detect: a Caddy JSON config parses as a JSON object; a native
    // Caddyfile does not. Adapt a Caddyfile to JSON first, then compile.
    let json_source = if crate::is_caddy_json(&source, config_path) {
        source
    } else {
        let name = config_path.to_string_lossy();
        let (json, warnings) = crate::caddyfile::adapt_to_string(&source, &name)
            .with_context(|| format!("failed to adapt {}", config_path.display()))?;
        for warning in &warnings {
            eprintln!("warning: {warning}");
        }
        json
    };

    let (generated, warnings) =
        crate::caddy_compile::compile_caddy_json_collecting(&json_source)
            .with_context(|| format!("failed to compile {}", config_path.display()))?;
    for warning in &warnings {
        eprintln!("warning: {warning}");
    }

    let object = compile_middleware_to_object(&generated)
        .context("failed to compile generated middleware to an eBPF object")?;

    build_tarball(&object).context("failed to assemble in-memory site tarball")
}

/// Create an anonymous in-memory file. The fd is left inheritable (no
/// `MFD_CLOEXEC`) so the clang/llc child processes can reach its contents via
/// `/proc/self/fd/<fd>`.
fn make_memfd(name: &str) -> Result<File> {
    let cname = std::ffi::CString::new(name).expect("memfd name has no interior NUL");
    let fd = memfd_create(cname.as_c_str(), MFdFlags::empty())
        .with_context(|| format!("memfd_create({name}) failed"))?;
    Ok(File::from(fd))
}

fn fd_path(file: &File) -> String {
    proc_fd_path(file.as_raw_fd())
}

fn proc_fd_path(fd: RawFd) -> String {
    format!("/proc/self/fd/{fd}")
}

/// Compile the generated middleware C into an eBPF object, entirely in memory.
/// The C source and the `.bc`/`.o` artifacts live in `memfd`s; only the static
/// SDK headers are written to a temporary directory for clang's include path.
fn compile_middleware_to_object(c_source: &str) -> Result<Vec<u8>> {
    let mut c_memfd = make_memfd("caddy.c")?;
    c_memfd
        .write_all(c_source.as_bytes())
        .context("failed to write generated C into memfd")?;
    c_memfd.flush().ok();

    let bc_memfd = make_memfd("caddy.bc")?;
    let mut o_memfd = make_memfd("caddy.o")?;

    let header_dir = write_sdk_headers()?;
    let result = (|| {
        // clang: C (memfd, no extension -> force `-x c`) -> LLVM bitcode (memfd).
        let clang_status = Command::new("clang")
            .args([
                "-O2",
                "-Wall",
                "-target",
                "bpf",
                "-fno-builtin",
                "-emit-llvm",
                "-x",
                "c",
                "-c",
            ])
            .arg("-I")
            .arg(&header_dir)
            .arg(fd_path(&c_memfd))
            .arg("-o")
            .arg(fd_path(&bc_memfd))
            .stdout(Stdio::null())
            .status()
            .context("failed to run clang")?;
        if !clang_status.success() {
            bail!("clang failed to compile the generated middleware");
        }

        // llc: LLVM bitcode (memfd) -> BPF object (memfd).
        let llc_status = Command::new("llc")
            .args([
                "-march=bpf",
                "-bpf-stack-size=4096",
                "-mcpu=v3",
                "-filetype=obj",
            ])
            .arg(fd_path(&bc_memfd))
            .arg("-o")
            .arg(fd_path(&o_memfd))
            .stdout(Stdio::null())
            .status()
            .context("failed to run llc")?;
        if !llc_status.success() {
            bail!("llc failed to assemble the generated middleware");
        }
        Ok(())
    })();
    let _ = fs::remove_dir_all(&header_dir);
    result?;

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
        bail!("compiled middleware object is empty");
    }
    Ok(object)
}

/// Materialize the SDK headers into a fresh temporary directory and return it,
/// for use as clang's include path. The caller removes it.
fn write_sdk_headers() -> Result<std::path::PathBuf> {
    let dir = std::env::temp_dir().join(format!("zeroserve-caddy-{}", Ulid::new()));
    fs::create_dir_all(&dir)
        .with_context(|| format!("failed to create temp header dir {}", dir.display()))?;
    fs::write(dir.join("zeroserve.h"), ZEROSERVE_H)
        .with_context(|| format!("failed to write headers into {}", dir.display()))?;
    fs::write(dir.join("zeroserve_caddy.h"), ZEROSERVE_CADDY_H)
        .with_context(|| format!("failed to write headers into {}", dir.display()))?;
    Ok(dir)
}

/// Assemble a tar archive containing the single compiled middleware object.
fn build_tarball(object: &[u8]) -> Result<Vec<u8>> {
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header
        .set_path(SCRIPT_TAR_PATH)
        .context("invalid script tar path")?;
    header.set_size(object.len() as u64);
    header.set_mode(0o644);
    header.set_mtime(0);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_cksum();
    builder
        .append(&header, object)
        .context("failed to append middleware object to tar")?;
    builder
        .into_inner()
        .context("failed to finalize tar stream")
}

/// Load the site for this run: from the in-memory `--caddy` tarball when one is
/// attached (rebuilt into a fresh memfd, so reloads work without disk), or from
/// the on-disk `tar_path` otherwise.
pub fn load_site(config: &StaticConfig) -> Result<Site> {
    match &config.caddy_tarball {
        Some(bytes) => {
            let file = memfd_from_bytes("zeroserve-caddy-site", bytes)?;
            Site::load_from_file(file, config.max_rate_limit_buckets)
                .context("failed to load in-memory caddy site tarball")
        }
        None => Site::load(&config.tar_path, config.max_rate_limit_buckets),
    }
}

/// Build a fresh in-memory file (memfd) seeded with `bytes`, for use as a site
/// tarball backing file. The returned `File` is seekable and supports
/// positional reads, exactly like an on-disk tarball.
pub fn memfd_from_bytes(name: &str, bytes: &[u8]) -> Result<File> {
    let cname = std::ffi::CString::new(name).expect("memfd name has no interior NUL");
    // CLOEXEC is fine here: this fd is only read in-process by the runtime.
    let fd = memfd_create(cname.as_c_str(), MFdFlags::MFD_CLOEXEC)
        .with_context(|| format!("memfd_create({name}) failed"))?;
    let mut file = File::from(fd);
    file.write_all(bytes)
        .context("failed to write tarball into memfd")?;
    file.seek(SeekFrom::Start(0))
        .context("failed to rewind tarball memfd")?;
    Ok(file)
}
