use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result, anyhow, bail};
use boring::hpke::HpkeKey;
use boring::pkey::{PKey, Private};
use boring::ssl::SslEchKeys;
use boring::x509::X509;

use crate::boringtls::{BoringAcceptor, ServerIdentity};
use crate::config::StaticConfig;
use crate::ech::key::EchKeySet;

#[derive(Clone)]
pub struct TlsRuntime {
    pub acceptor: BoringAcceptor,
    /// True when ECH keys are loaded (the listener still serves plain TLS too).
    pub ech_enabled: bool,
    /// The ECH public name to report as the outer SNI when ECH is accepted.
    /// `Some` only when all loaded configs share one public name (so it is
    /// unambiguous); `None` otherwise (zero or multiple distinct names).
    pub ech_public_name: Option<String>,
}

pub fn load_tls_if_configured(config: &Arc<StaticConfig>) -> Result<Option<TlsRuntime>> {
    match &config.tls_addr {
        Some(_addr) => {
            // Load ECH keys first (if configured) so we can install them on the
            // context during construction.
            let ech_keys = match &config.ech_key_path {
                Some(path) => {
                    let set = EchKeySet::load(path)
                        .with_context(|| format!("loading ECH keys from {}", path.display()))?;
                    if set.pairs.is_empty() {
                        bail!("ECH key set is empty");
                    }
                    Some(set)
                }
                None => None,
            };

            let ech_enabled = ech_keys.is_some();

            // The distinct ECH public names. When a client connects to one of
            // these without a decryptable inner ClientHello and we hold no
            // certificate covering it, the acceptor transparently relays the
            // raw TLS connection to the real public-name server.
            let relay_public_names: Vec<String> = match &ech_keys {
                Some(set) => {
                    let mut names: Vec<String> = set
                        .pairs
                        .iter()
                        .map(|p| p.config.public_name.clone())
                        .collect();
                    names.sort_unstable();
                    names.dedup();
                    names
                }
                None => Vec::new(),
            };

            let configure = |builder: &mut boring::ssl::SslContextBuilder| {
                if let Some(set) = &ech_keys {
                    let mut ech = SslEchKeys::builder()
                        .map_err(|e| anyhow!("SSL_ECH_KEYS_new failed: {e}"))?;
                    for pair in &set.pairs {
                        // BoringSSL only ships an X25519 HPKE key constructor
                        // (the `dhkem_p256_sha256` name is a boring misnomer —
                        // its body uses EVP_hpke_x25519_hkdf_sha256), which
                        // matches the suite our keygen emits.
                        let key = HpkeKey::dhkem_p256_sha256(&pair.private_key).map_err(|e| {
                            anyhow!(
                                "invalid ECH HPKE key (config_id 0x{:02x}): {e}",
                                pair.config.config_id
                            )
                        })?;
                        // is_retry_config = true: advertise every loaded config
                        // in `retry_configs` when a client offers a stale one.
                        ech.add_key(true, &pair.config.encode(), key).map_err(|e| {
                            anyhow!(
                                "SSL_ECH_KEYS_add failed (config_id 0x{:02x}): {e}",
                                pair.config.config_id
                            )
                        })?;
                    }
                    let ech = ech.build();
                    builder
                        .set_ech_keys(&ech)
                        .map_err(|e| anyhow!("SSL_CTX_set1_ech_keys failed: {e}"))?;
                }
                Ok(())
            };

            let acceptor = if let Some(cert_dir) = &config.cert_dir_path {
                let identities = load_cert_dir(cert_dir).with_context(|| {
                    format!("loading TLS certificates from {}", cert_dir.display())
                })?;
                eprintln!(
                    "loaded {} TLS certificate identity(s) from {}",
                    identities.len(),
                    cert_dir.display()
                );
                BoringAcceptor::build_with_identities(
                    identities,
                    relay_public_names.clone(),
                    configure,
                )?
            } else {
                let cert = config
                    .cert_path
                    .as_deref()
                    .ok_or_else(|| anyhow!("TLS certificate path missing"))?;
                let key = config
                    .key_path
                    .as_deref()
                    .ok_or_else(|| anyhow!("TLS private key path missing"))?;
                BoringAcceptor::build(cert, key, relay_public_names.clone(), configure)?
            };

            let mut ech_public_name = None;
            if let Some(set) = &ech_keys {
                use base64ct::Encoding as _;
                let list_b64 = base64ct::Base64::encode_string(&set.config_list_bytes());
                let mut names: Vec<&str> = set
                    .pairs
                    .iter()
                    .map(|p| p.config.public_name.as_str())
                    .collect();
                eprintln!(
                    "ECH enabled: {} key(s), public_name(s)={:?}; the TLS cert must cover each name. Publish ech=\"{}\"",
                    set.pairs.len(),
                    names,
                    list_b64
                );
                eprintln!(
                    "ECH relay enabled for public name(s) {:?}: connections to those names without a decryptable inner ClientHello and without a matching certificate will be transparently relayed to the real server on port 443",
                    relay_public_names
                );
                // Report the outer SNI only when it is unambiguous.
                names.sort_unstable();
                names.dedup();
                if let [single] = names.as_slice() {
                    ech_public_name = Some(single.to_string());
                }
            }

            Ok(Some(TlsRuntime {
                acceptor,
                ech_enabled,
                ech_public_name,
            }))
        }
        None => Ok(None),
    }
}

struct CertFile {
    path: PathBuf,
    certs: Vec<X509>,
}

struct KeyFile {
    path: PathBuf,
    key: PKey<Private>,
}

fn load_cert_dir(dir: &Path) -> Result<Vec<ServerIdentity>> {
    let mut paths = fs::read_dir(dir)
        .with_context(|| format!("reading TLS certificate directory {}", dir.display()))?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()
        .with_context(|| format!("reading entries in {}", dir.display()))?;
    paths.sort();

    let mut cert_files = Vec::new();
    let mut key_files = Vec::new();
    for path in paths {
        let metadata = fs::metadata(&path)
            .with_context(|| format!("stat TLS directory entry {}", path.display()))?;
        if !metadata.is_file() {
            continue;
        }

        let data = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
        if let Ok(certs) = X509::stack_from_pem(&data) {
            if !certs.is_empty() {
                cert_files.push(CertFile {
                    path: path.clone(),
                    certs,
                });
            }
        }
        if let Ok(key) = PKey::private_key_from_pem(&data) {
            key_files.push(KeyFile {
                path: path.clone(),
                key,
            });
        }
    }

    if cert_files.is_empty() {
        bail!("no TLS certificate PEMs found in {}", dir.display());
    }
    if key_files.is_empty() {
        bail!("no TLS private key PEMs found in {}", dir.display());
    }

    let mut identities = Vec::new();
    for cert_file in cert_files {
        let leaf = cert_file
            .certs
            .into_iter()
            .next()
            .expect("cert files are non-empty");
        let public_key = leaf
            .public_key()
            .with_context(|| format!("reading public key from {}", cert_file.path.display()))?;
        let Some(key_file) = key_files
            .iter()
            .find(|key_file| public_key.public_eq(&key_file.key))
        else {
            eprintln!(
                "warning: no matching private key found for TLS certificate {}",
                cert_file.path.display()
            );
            continue;
        };
        identities.push(ServerIdentity::from_leaf(
            cert_file.path,
            key_file.path.clone(),
            leaf,
        ));
    }

    if identities.is_empty() {
        bail!(
            "no TLS certificate PEMs in {} matched any private key PEM",
            dir.display()
        );
    }
    Ok(identities)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cert_dir_matches_certificate_to_key_by_public_key() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let cert = root.join("certificate.pem");
        let key = root.join("key.pem");
        if !cert.exists() || !key.exists() {
            eprintln!("skipping: test cert/key not present");
            return;
        }

        let dir =
            std::env::temp_dir().join(format!("zeroserve-cert-dir-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).unwrap();
        fs::copy(&cert, dir.join("02-cert.pem")).unwrap();
        fs::copy(&key, dir.join("01-key.pem")).unwrap();

        let identities = load_cert_dir(&dir).unwrap();
        assert_eq!(identities.len(), 1);

        fs::remove_dir_all(&dir).unwrap();
    }
}
