use crate::builder::{ConfigBuilder, WantsVerifier};
use crate::client::{handy, ClientConfig, ResolvesClientCert};
use crate::error::Error;
use crate::key_log::NoKeyLog;
use crate::kx::SupportedKxGroup;
use crate::suites::SupportedCipherSuite;
use crate::verify;
use crate::{anchors, key, versions};

use super::client_conn::Resumption;

use std::marker::PhantomData;
use std::sync::Arc;

impl ConfigBuilder<ClientConfig, WantsVerifier> {
    /// Choose how to verify server certificates.
    pub fn with_root_certificates(
        self,
        root_store: anchors::RootCertStore,
    ) -> ConfigBuilder<ClientConfig, WantsClientCert> {
        ConfigBuilder {
            state: WantsClientCert {
                cipher_suites: self.state.cipher_suites,
                kx_groups: self.state.kx_groups,
                versions: self.state.versions,
                verifier: Arc::new(verify::WebPkiVerifier::new(root_store)),
            },
            side: PhantomData,
        }
    }

    #[cfg(feature = "dangerous_configuration")]
    /// Set a custom certificate verifier.
    pub fn with_custom_certificate_verifier(
        self,
        verifier: Arc<dyn verify::ServerCertVerifier>,
    ) -> ConfigBuilder<ClientConfig, WantsClientCert> {
        ConfigBuilder {
            state: WantsClientCert {
                cipher_suites: self.state.cipher_suites,
                kx_groups: self.state.kx_groups,
                versions: self.state.versions,
                verifier,
            },
            side: PhantomData::default(),
        }
    }
}

/// A config builder state where the caller needs to supply whether and how to provide a client
/// certificate.
///
/// For more information, see the [`ConfigBuilder`] documentation.
#[derive(Clone, Debug)]
pub struct WantsClientCert {
    cipher_suites: Vec<SupportedCipherSuite>,
    kx_groups: Vec<&'static SupportedKxGroup>,
    versions: versions::EnabledVersions,
    verifier: Arc<dyn verify::ServerCertVerifier>,
}

impl ConfigBuilder<ClientConfig, WantsClientCert> {
    /// Sets a single certificate chain and matching private key for use
    /// in client authentication.
    ///
    /// `cert_chain` is a vector of DER-encoded certificates.
    /// `key_der` is a DER-encoded RSA, ECDSA, or Ed25519 private key.
    ///
    /// This function fails if `key_der` is invalid.
    pub fn with_single_cert(
        self,
        cert_chain: Vec<key::Certificate>,
        key_der: key::PrivateKey,
    ) -> Result<ClientConfig, Error> {
        let resolver = handy::AlwaysResolvesClientCert::new(cert_chain, &key_der)?;
        Ok(self.with_client_cert_resolver(Arc::new(resolver)))
    }

    /// Do not support client auth.
    pub fn with_no_client_auth(self) -> ClientConfig {
        self.with_client_cert_resolver(Arc::new(handy::FailResolveClientCert {}))
    }

    /// Sets a custom [`ResolvesClientCert`].
    pub fn with_client_cert_resolver(
        self,
        client_auth_cert_resolver: Arc<dyn ResolvesClientCert>,
    ) -> ClientConfig {
        ClientConfig {
            cipher_suites: self.state.cipher_suites,
            kx_groups: self.state.kx_groups,
            alpn_protocols: Vec::new(),
            resumption: Resumption::default(),
            max_fragment_size: None,
            client_auth_cert_resolver,
            versions: self.state.versions,
            enable_sni: true,
            verifier: self.state.verifier,
            key_log: Arc::new(NoKeyLog {}),
            #[cfg(feature = "secret_extraction")]
            enable_secret_extraction: false,
            enable_early_data: false,
        }
    }
}
