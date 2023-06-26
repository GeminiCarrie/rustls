use crate::anchors::{OwnedTrustAnchor, RootCertStore};
use crate::client::ServerName;
use crate::enums::SignatureScheme;
use crate::error::{CertificateError, Error, PeerMisbehaved};
use crate::key::Certificate;
#[cfg(feature = "logging")]
use crate::log::{debug, trace, warn};
use crate::msgs::handshake::DistinguishedName;
use crate::verify::{
    ClientCertVerified, ClientCertVerifier, DigitallySignedStruct, HandshakeSignatureValid,
    ServerCertVerified, ServerCertVerifier,
};

use std::sync::Arc;
use std::time::SystemTime;

type SignatureAlgorithms = &'static [&'static webpki::SignatureAlgorithm];

/// Which signature verification mechanisms we support.  No particular
/// order.
static SUPPORTED_SIG_ALGS: SignatureAlgorithms = &[
    &webpki::ECDSA_P256_SHA256,
    &webpki::ECDSA_P256_SHA384,
    &webpki::ECDSA_P384_SHA256,
    &webpki::ECDSA_P384_SHA384,
    &webpki::ED25519,
    &webpki::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
    &webpki::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
    &webpki::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
    &webpki::RSA_PKCS1_2048_8192_SHA256,
    &webpki::RSA_PKCS1_2048_8192_SHA384,
    &webpki::RSA_PKCS1_2048_8192_SHA512,
    &webpki::RSA_PKCS1_3072_8192_SHA384,
];

impl ServerCertVerifier for WebPkiVerifier {
    /// Will verify the certificate is valid in the following ways:
    /// - Signed by a  trusted `RootCertStore` CA
    /// - Not Expired
    /// - Valid for DNS entry
    fn verify_server_cert(
        &self,
        end_entity: &Certificate,
        intermediates: &[Certificate],
        server_name: &ServerName,
        scts: &mut dyn Iterator<Item = &[u8]>,
        ocsp_response: &[u8],
        now: SystemTime,
    ) -> Result<ServerCertVerified, Error> {
        let (cert, chain, trustroots) = prepare(end_entity, intermediates, &self.roots)?;
        let webpki_now = webpki::Time::try_from(now).map_err(|_| Error::FailedToGetCurrentTime)?;

        let cert = cert
            .verify_is_valid_tls_server_cert(
                SUPPORTED_SIG_ALGS,
                &webpki::TlsServerTrustAnchors(&trustroots),
                &chain,
                webpki_now,
            )
            .map_err(pki_error)
            .map(|_| cert)?;

        if let Some(policy) = &self.ct_policy {
            policy.verify(end_entity, now, scts)?;
        }

        if !ocsp_response.is_empty() {
            trace!("Unvalidated OCSP response: {:?}", ocsp_response.to_vec());
        }

        match server_name {
            ServerName::DnsName(dns_name) => {
                // unlikely error because dns_name::DnsNameRef and webpki::DnsNameRef
                // should have the same encoding rules.
                let dns_name = webpki::DnsNameRef::try_from_ascii_str(dns_name.as_ref())
                    .map_err(|_| Error::InvalidCertificate(CertificateError::BadEncoding))?;
                let name = webpki::SubjectNameRef::DnsName(dns_name);
                cert.verify_is_valid_for_subject_name(name)
                    .map_err(pki_error)
                    .map(|_| ServerCertVerified::assertion())
            }
            ServerName::IpAddress(ip_addr) => {
                let ip_addr = webpki::IpAddr::from(*ip_addr);
                cert.verify_is_valid_for_subject_name(webpki::SubjectNameRef::IpAddress(
                    webpki::IpAddrRef::from(&ip_addr),
                ))
                .map_err(pki_error)
                .map(|_| ServerCertVerified::assertion())
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &Certificate,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Self::default_verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &Certificate,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Self::default_verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        Self::default_supported_verify_schemes()
    }

    fn request_scts(&self) -> bool {
        self.ct_policy.is_some()
    }
}

/// Default `ServerCertVerifier`, see the trait impl for more information.
#[allow(unreachable_pub)]
#[cfg_attr(docsrs, doc(cfg(feature = "dangerous_configuration")))]
pub struct WebPkiVerifier {
    roots: RootCertStore,
    ct_policy: Option<CertificateTransparencyPolicy>,
}

#[allow(unreachable_pub)]
impl WebPkiVerifier {
    /// Constructs a new `WebPkiVerifier`.
    ///
    /// `roots` is the set of trust anchors to trust for issuing server certs.
    ///
    /// `ct_logs` is the list of logs that are trusted for Certificate
    /// Transparency. Currently CT log enforcement is opportunistic; see
    /// <https://github.com/rustls/rustls/issues/479>.
    pub fn new(roots: RootCertStore, ct_policy: Option<CertificateTransparencyPolicy>) -> Self {
        Self { roots, ct_policy }
    }

    /// Which signature verification schemes the `webpki` crate supports.
    pub fn default_supported_verify_schemes() -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA256,
        ]
    }

    /// An full implementation of `ServerCertVerifier::verify_tls12_signature` or
    /// `ClientCertVerifier::verify_tls12_signature`.
    pub fn default_verify_tls12_signature(
        message: &[u8],
        cert: &Certificate,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_signed_struct(message, cert, dss)
    }

    /// An full implementation of `ServerCertVerifier::verify_tls13_signature` or
    /// `ClientCertVerifier::verify_tls13_signature`.
    pub fn default_verify_tls13_signature(
        message: &[u8],
        cert: &Certificate,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13(message, cert, dss)
    }
}

/// Policy for enforcing Certificate Transparency.
///
/// Because Certificate Transparency logs are sharded on a per-year basis and can be trusted or
/// distrusted relatively quickly, rustls stores a validation deadline. Server certificates will
/// be validated against the configured CT logs until the deadline expires. After the deadline,
/// certificates will no longer be validated, and a warning message will be logged. The deadline
/// may vary depending on how often you deploy builds with updated dependencies.
#[allow(unreachable_pub)]
#[cfg_attr(docsrs, doc(cfg(feature = "dangerous_configuration")))]
pub struct CertificateTransparencyPolicy {
    logs: &'static [&'static sct::Log<'static>],
    validation_deadline: SystemTime,
}

impl CertificateTransparencyPolicy {
    /// Create a new policy.
    #[allow(unreachable_pub)]
    pub fn new(
        logs: &'static [&'static sct::Log<'static>],
        validation_deadline: SystemTime,
    ) -> Self {
        Self {
            logs,
            validation_deadline,
        }
    }

    fn verify(
        &self,
        cert: &Certificate,
        now: SystemTime,
        scts: &mut dyn Iterator<Item = &[u8]>,
    ) -> Result<(), Error> {
        if self.logs.is_empty() {
            return Ok(());
        } else if self
            .validation_deadline
            .duration_since(now)
            .is_err()
        {
            warn!("certificate transparency logs have expired, validation disabled");
            return Ok(());
        }

        let now = unix_time_millis(now)?;
        let mut last_sct_error = None;
        for sct in scts {
            #[cfg_attr(not(feature = "logging"), allow(unused_variables))]
            match sct::verify_sct(&cert.0, sct, now, self.logs) {
                Ok(index) => {
                    debug!(
                        "Valid SCT signed by {} on {}",
                        self.logs[index].operated_by, self.logs[index].description
                    );
                    return Ok(());
                }
                Err(e) => {
                    if e.should_be_fatal() {
                        return Err(Error::InvalidSct(e));
                    }
                    debug!("SCT ignored because {:?}", e);
                    last_sct_error = Some(e);
                }
            }
        }

        /* If we were supplied with some logs, and some SCTs,
         * but couldn't verify any of them, fail the handshake. */
        if let Some(last_sct_error) = last_sct_error {
            warn!("No valid SCTs provided");
            return Err(Error::InvalidSct(last_sct_error));
        }

        Ok(())
    }
}

type CertChainAndRoots<'a, 'b> = (
    webpki::EndEntityCert<'a>,
    Vec<&'a [u8]>,
    Vec<webpki::TrustAnchor<'b>>,
);

fn prepare<'a, 'b>(
    end_entity: &'a Certificate,
    intermediates: &'a [Certificate],
    roots: &'b RootCertStore,
) -> Result<CertChainAndRoots<'a, 'b>, Error> {
    // EE cert must appear first.
    let cert = webpki::EndEntityCert::try_from(end_entity.0.as_ref()).map_err(pki_error)?;

    let intermediates: Vec<&'a [u8]> = intermediates
        .iter()
        .map(|cert| cert.0.as_ref())
        .collect();

    let trustroots: Vec<webpki::TrustAnchor> = roots
        .roots
        .iter()
        .map(OwnedTrustAnchor::to_trust_anchor)
        .collect();

    Ok((cert, intermediates, trustroots))
}

/// A `ClientCertVerifier` that will ensure that every client provides a trusted
/// certificate, without any name checking.
pub struct AllowAnyAuthenticatedClient {
    roots: RootCertStore,
    subjects: Vec<DistinguishedName>,
}

impl AllowAnyAuthenticatedClient {
    /// Construct a new `AllowAnyAuthenticatedClient`.
    ///
    /// `roots` is the list of trust anchors to use for certificate validation.
    pub fn new(roots: RootCertStore) -> Self {
        Self {
            subjects: roots
                .roots
                .iter()
                .map(|r| r.subject().clone())
                .collect(),
            roots,
        }
    }

    /// Wrap this verifier in an [`Arc`] and coerce it to `dyn ClientCertVerifier`
    #[inline(always)]
    pub fn boxed(self) -> Arc<dyn ClientCertVerifier> {
        // This function is needed because `ClientCertVerifier` is only reachable if the
        // `dangerous_configuration` feature is enabled, which makes coercing hard to outside users
        Arc::new(self)
    }
}

impl ClientCertVerifier for AllowAnyAuthenticatedClient {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_root_subjects(&self) -> &[DistinguishedName] {
        &self.subjects
    }

    fn verify_client_cert(
        &self,
        end_entity: &Certificate,
        intermediates: &[Certificate],
        now: SystemTime,
    ) -> Result<ClientCertVerified, Error> {
        let (cert, chain, trustroots) = prepare(end_entity, intermediates, &self.roots)?;
        let now = webpki::Time::try_from(now).map_err(|_| Error::FailedToGetCurrentTime)?;
        cert.verify_is_valid_tls_client_cert(
            SUPPORTED_SIG_ALGS,
            &webpki::TlsClientTrustAnchors(&trustroots),
            &chain,
            now,
        )
        .map_err(pki_error)
        .map(|_| ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &Certificate,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        WebPkiVerifier::default_verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &Certificate,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        WebPkiVerifier::default_verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        WebPkiVerifier::default_supported_verify_schemes()
    }
}

/// A `ClientCertVerifier` that will allow both anonymous and authenticated
/// clients, without any name checking.
///
/// Client authentication will be requested during the TLS handshake. If the
/// client offers a certificate then this acts like
/// `AllowAnyAuthenticatedClient`, otherwise this acts like `NoClientAuth`.
pub struct AllowAnyAnonymousOrAuthenticatedClient {
    inner: AllowAnyAuthenticatedClient,
}

impl AllowAnyAnonymousOrAuthenticatedClient {
    /// Construct a new `AllowAnyAnonymousOrAuthenticatedClient`.
    ///
    /// `roots` is the list of trust anchors to use for certificate validation.
    pub fn new(roots: RootCertStore) -> Self {
        Self {
            inner: AllowAnyAuthenticatedClient::new(roots),
        }
    }

    /// Wrap this verifier in an [`Arc`] and coerce it to `dyn ClientCertVerifier`
    #[inline(always)]
    pub fn boxed(self) -> Arc<dyn ClientCertVerifier> {
        // This function is needed because `ClientCertVerifier` is only reachable if the
        // `dangerous_configuration` feature is enabled, which makes coercing hard to outside users
        Arc::new(self)
    }
}

impl ClientCertVerifier for AllowAnyAnonymousOrAuthenticatedClient {
    fn offer_client_auth(&self) -> bool {
        self.inner.offer_client_auth()
    }

    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn client_auth_root_subjects(&self) -> &[DistinguishedName] {
        self.inner.client_auth_root_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &Certificate,
        intermediates: &[Certificate],
        now: SystemTime,
    ) -> Result<ClientCertVerified, Error> {
        self.inner
            .verify_client_cert(end_entity, intermediates, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &Certificate,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        WebPkiVerifier::default_verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &Certificate,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        WebPkiVerifier::default_verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        WebPkiVerifier::default_supported_verify_schemes()
    }
}

fn pki_error(error: webpki::Error) -> Error {
    use webpki::Error::*;
    match error {
        BadDer | BadDerTime => CertificateError::BadEncoding.into(),
        CertNotValidYet => CertificateError::NotValidYet.into(),
        CertExpired | InvalidCertValidity => CertificateError::Expired.into(),
        UnknownIssuer => CertificateError::UnknownIssuer.into(),
        CertNotValidForName => CertificateError::NotValidForName.into(),

        InvalidSignatureForPublicKey
        | UnsupportedSignatureAlgorithm
        | UnsupportedSignatureAlgorithmForPublicKey => CertificateError::BadSignature.into(),
        _ => CertificateError::Other(Arc::new(error)).into(),
    }
}

static ECDSA_SHA256: SignatureAlgorithms =
    &[&webpki::ECDSA_P256_SHA256, &webpki::ECDSA_P384_SHA256];

static ECDSA_SHA384: SignatureAlgorithms =
    &[&webpki::ECDSA_P256_SHA384, &webpki::ECDSA_P384_SHA384];

static ED25519: SignatureAlgorithms = &[&webpki::ED25519];

static RSA_SHA256: SignatureAlgorithms = &[&webpki::RSA_PKCS1_2048_8192_SHA256];
static RSA_SHA384: SignatureAlgorithms = &[&webpki::RSA_PKCS1_2048_8192_SHA384];
static RSA_SHA512: SignatureAlgorithms = &[&webpki::RSA_PKCS1_2048_8192_SHA512];
static RSA_PSS_SHA256: SignatureAlgorithms = &[&webpki::RSA_PSS_2048_8192_SHA256_LEGACY_KEY];
static RSA_PSS_SHA384: SignatureAlgorithms = &[&webpki::RSA_PSS_2048_8192_SHA384_LEGACY_KEY];
static RSA_PSS_SHA512: SignatureAlgorithms = &[&webpki::RSA_PSS_2048_8192_SHA512_LEGACY_KEY];

fn convert_scheme(scheme: SignatureScheme) -> Result<SignatureAlgorithms, Error> {
    match scheme {
        // nb. for TLS1.2 the curve is not fixed by SignatureScheme.
        SignatureScheme::ECDSA_NISTP256_SHA256 => Ok(ECDSA_SHA256),
        SignatureScheme::ECDSA_NISTP384_SHA384 => Ok(ECDSA_SHA384),

        SignatureScheme::ED25519 => Ok(ED25519),

        SignatureScheme::RSA_PKCS1_SHA256 => Ok(RSA_SHA256),
        SignatureScheme::RSA_PKCS1_SHA384 => Ok(RSA_SHA384),
        SignatureScheme::RSA_PKCS1_SHA512 => Ok(RSA_SHA512),

        SignatureScheme::RSA_PSS_SHA256 => Ok(RSA_PSS_SHA256),
        SignatureScheme::RSA_PSS_SHA384 => Ok(RSA_PSS_SHA384),
        SignatureScheme::RSA_PSS_SHA512 => Ok(RSA_PSS_SHA512),

        _ => Err(PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme.into()),
    }
}

fn verify_sig_using_any_alg(
    cert: &webpki::EndEntityCert,
    algs: SignatureAlgorithms,
    message: &[u8],
    sig: &[u8],
) -> Result<(), webpki::Error> {
    // TLS doesn't itself give us enough info to map to a single webpki::SignatureAlgorithm.
    // Therefore, convert_algs maps to several and we try them all.
    for alg in algs {
        match cert.verify_signature(alg, message, sig) {
            Err(webpki::Error::UnsupportedSignatureAlgorithmForPublicKey) => continue,
            res => return res,
        }
    }

    Err(webpki::Error::UnsupportedSignatureAlgorithmForPublicKey)
}

fn verify_signed_struct(
    message: &[u8],
    cert: &Certificate,
    dss: &DigitallySignedStruct,
) -> Result<HandshakeSignatureValid, Error> {
    let possible_algs = convert_scheme(dss.scheme)?;
    let cert = webpki::EndEntityCert::try_from(cert.0.as_ref()).map_err(pki_error)?;

    verify_sig_using_any_alg(&cert, possible_algs, message, dss.signature())
        .map_err(pki_error)
        .map(|_| HandshakeSignatureValid::assertion())
}

fn convert_alg_tls13(
    scheme: SignatureScheme,
) -> Result<&'static webpki::SignatureAlgorithm, Error> {
    use crate::enums::SignatureScheme::*;

    match scheme {
        ECDSA_NISTP256_SHA256 => Ok(&webpki::ECDSA_P256_SHA256),
        ECDSA_NISTP384_SHA384 => Ok(&webpki::ECDSA_P384_SHA384),
        ED25519 => Ok(&webpki::ED25519),
        RSA_PSS_SHA256 => Ok(&webpki::RSA_PSS_2048_8192_SHA256_LEGACY_KEY),
        RSA_PSS_SHA384 => Ok(&webpki::RSA_PSS_2048_8192_SHA384_LEGACY_KEY),
        RSA_PSS_SHA512 => Ok(&webpki::RSA_PSS_2048_8192_SHA512_LEGACY_KEY),
        _ => Err(PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme.into()),
    }
}

fn verify_tls13(
    msg: &[u8],
    cert: &Certificate,
    dss: &DigitallySignedStruct,
) -> Result<HandshakeSignatureValid, Error> {
    let alg = convert_alg_tls13(dss.scheme)?;

    let cert = webpki::EndEntityCert::try_from(cert.0.as_ref()).map_err(pki_error)?;

    cert.verify_signature(alg, msg, dss.signature())
        .map_err(pki_error)
        .map(|_| HandshakeSignatureValid::assertion())
}

fn unix_time_millis(now: SystemTime) -> Result<u64, Error> {
    now.duration_since(std::time::UNIX_EPOCH)
        .map(|dur| dur.as_secs())
        .map_err(|_| Error::FailedToGetCurrentTime)
        .and_then(|secs| {
            secs.checked_mul(1000)
                .ok_or(Error::FailedToGetCurrentTime)
        })
}
