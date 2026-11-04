//! TLS setup shared by every outbound HTTPS client: DoH upstreams, their
//! probes and blocklist downloads.

use std::sync::Arc;

use rustls::{ClientConfig, RootCertStore};

/// A reqwest builder that uses our rustls config: the `ring` provider, TLS
/// 1.2 and 1.3, the system trust store, ALPN `h2` then `http/1.1`, SNI on,
/// and certificate plus hostname verification by rustls' WebPKI verifier.
/// Nothing here is process-global, so no default crypto provider is needed.
#[allow(clippy::disallowed_methods)] // the one place allowed to call it
pub fn client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder().tls_backend_preconfigured(config(system_roots()))
}

/// The system trust store, through rustls-native-certs: only the
/// `SSL_CERT_FILE` / `SSL_CERT_DIR` bundles when either is set (the scratch
/// image sets `SSL_CERT_FILE`), otherwise the platform store (the usual
/// OpenSSL paths on Linux, the keychains on macOS). No bundled roots.
/// Unparsable entries are skipped; with no roots at all every handshake fails,
/// so that case is logged where an operator will see it.
fn system_roots() -> RootCertStore {
    let found = rustls_native_certs::load_native_certs();
    let mut roots = RootCertStore::empty();
    let (_, unparsable) = roots.add_parsable_certificates(found.certs);
    if roots.is_empty() {
        let error = found.errors.first().map_or_else(|| "no certificates found".to_string(), ToString::to_string);
        crate::log::log(
            "warn",
            "tls_no_trusted_roots",
            &[("unparsable", unparsable.to_string()), ("error", error), ("hint", "check SSL_CERT_FILE".to_string())],
        );
    }
    roots
}

/// The same settings reqwest 0.12 built for `rustls-tls-native-roots`.
fn config(roots: RootCertStore) -> ClientConfig {
    let mut config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_protocol_versions(rustls::ALL_VERSIONS)
        .expect("ring supports TLS 1.2 and 1.3")
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    config
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_keeps_the_0_12_settings() {
        let config = config(RootCertStore::empty());
        assert_eq!(config.alpn_protocols, [b"h2".to_vec(), b"http/1.1".to_vec()]);
        assert!(config.enable_sni);
        assert!(!config.enable_early_data, "no 0-RTT: early data can be replayed");
    }
}
