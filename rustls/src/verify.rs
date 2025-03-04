use std::fmt;

use crate::anchors::{OwnedTrustAnchor, RootCertStore};
use crate::client::ServerName;
use crate::enums::SignatureScheme;
use crate::error::{CertificateError, Error, InvalidMessage, PeerMisbehaved};
use crate::key::{Certificate, ParsedCertificate};
#[cfg(feature = "logging")]
use crate::log::trace;
use crate::msgs::base::PayloadU16;
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::handshake::DistinguishedName;

use ring::digest::Digest;

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

// Marker types.  These are used to bind the fact some verification
// (certificate chain or handshake signature) has taken place into
// protocol states.  We use this to have the compiler check that there
// are no 'goto fail'-style elisions of important checks before we
// reach the traffic stage.
//
// These types are public, but cannot be directly constructed.  This
// means their origins can be precisely determined by looking
// for their `assertion` constructors.

/// Zero-sized marker type representing verification of a signature.
#[derive(Debug)]
#[cfg_attr(docsrs, doc(cfg(feature = "dangerous_configuration")))]
pub struct HandshakeSignatureValid(());

impl HandshakeSignatureValid {
    /// Make a `HandshakeSignatureValid`
    pub fn assertion() -> Self {
        Self(())
    }
}

#[derive(Debug)]
pub(crate) struct FinishedMessageVerified(());

impl FinishedMessageVerified {
    pub(crate) fn assertion() -> Self {
        Self(())
    }
}

/// Zero-sized marker type representing verification of a server cert chain.
#[allow(unreachable_pub)]
#[derive(Debug)]
#[cfg_attr(docsrs, doc(cfg(feature = "dangerous_configuration")))]
pub struct ServerCertVerified(());

#[allow(unreachable_pub)]
impl ServerCertVerified {
    /// Make a `ServerCertVerified`
    pub fn assertion() -> Self {
        Self(())
    }
}

/// Zero-sized marker type representing verification of a client cert chain.
#[derive(Debug)]
#[cfg_attr(docsrs, doc(cfg(feature = "dangerous_configuration")))]
pub struct ClientCertVerified(());

impl ClientCertVerified {
    /// Make a `ClientCertVerified`
    pub fn assertion() -> Self {
        Self(())
    }
}

/// Something that can verify a server certificate chain, and verify
/// signatures made by certificates.
#[allow(unreachable_pub)]
#[cfg_attr(docsrs, doc(cfg(feature = "dangerous_configuration")))]
pub trait ServerCertVerifier: Send + Sync {
    /// Verify the end-entity certificate `end_entity` is valid for the
    /// hostname `dns_name` and chains to at least one trust anchor.
    ///
    /// `intermediates` contains all certificates other than `end_entity` that
    /// were sent as part of the server's [Certificate] message. It is in the
    /// same order that the server sent them and may be empty.
    ///
    /// Note that none of the certificates have been parsed yet, so it is the responsibility of
    /// the implementor to handle invalid data. It is recommended that the implementor returns
    /// [`Error::InvalidCertificate(CertificateError::BadEncoding)`] when these cases are encountered.
    ///
    /// [Certificate]: https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.2
    fn verify_server_cert(
        &self,
        end_entity: &Certificate,
        intermediates: &[Certificate],
        server_name: &ServerName,
        ocsp_response: &[u8],
        now: SystemTime,
    ) -> Result<ServerCertVerified, Error>;

    /// Verify a signature allegedly by the given server certificate.
    ///
    /// `message` is not hashed, and needs hashing during the verification.
    /// The signature and algorithm are within `dss`.  `cert` contains the
    /// public key to use.
    ///
    /// `cert` has already been validated by [`ServerCertVerifier::verify_server_cert`].
    ///
    /// If and only if the signature is valid, return `Ok(HandshakeSignatureValid)`.
    /// Otherwise, return an error -- rustls will send an alert and abort the
    /// connection.
    ///
    /// This method is only called for TLS1.2 handshakes.  Note that, in TLS1.2,
    /// SignatureSchemes such as `SignatureScheme::ECDSA_NISTP256_SHA256` are not
    /// in fact bound to the specific curve implied in their name.
    ///
    /// This trait method has a default implementation that uses webpki to verify
    /// the signature.
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &Certificate,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_signed_struct(message, cert, dss)
    }

    /// Verify a signature allegedly by the given server certificate.
    ///
    /// This method is only called for TLS1.3 handshakes.
    ///
    /// This method is very similar to `verify_tls12_signature`: but note the
    /// tighter ECDSA SignatureScheme semantics -- e.g. `SignatureScheme::ECDSA_NISTP256_SHA256`
    /// must only validate signatures using public keys on the right curve --
    /// rustls does not enforce this requirement for you.
    ///
    /// `cert` has already been validated by [`ServerCertVerifier::verify_server_cert`].
    ///
    /// If and only if the signature is valid, return `Ok(HandshakeSignatureValid)`.
    /// Otherwise, return an error -- rustls will send an alert and abort the
    /// connection.
    ///
    /// This trait method has a default implementation that uses webpki to verify
    /// the signature.
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &Certificate,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13(message, cert, dss)
    }

    /// Return the list of SignatureSchemes that this verifier will handle,
    /// in `verify_tls12_signature` and `verify_tls13_signature` calls.
    ///
    /// This should be in priority order, with the most preferred first.
    ///
    /// This trait method has a default implementation that reflects the schemes
    /// supported by webpki.
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        WebPkiVerifier::verification_schemes()
    }
}

impl fmt::Debug for dyn ServerCertVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "dyn ServerCertVerifier")
    }
}

/// Something that can verify a client certificate chain
#[allow(unreachable_pub)]
#[cfg_attr(docsrs, doc(cfg(feature = "dangerous_configuration")))]
pub trait ClientCertVerifier: Send + Sync {
    /// Returns `true` to enable the server to request a client certificate and
    /// `false` to skip requesting a client certificate. Defaults to `true`.
    fn offer_client_auth(&self) -> bool {
        true
    }

    /// Return `true` to require a client certificate and `false` to make
    /// client authentication optional.
    /// Defaults to `Some(self.offer_client_auth())`.
    fn client_auth_mandatory(&self) -> bool {
        self.offer_client_auth()
    }

    /// Returns the [Subjects] of the client authentication trust anchors to
    /// share with the client when requesting client authentication.
    ///
    /// These must be DER-encoded X.500 distinguished names, per RFC 5280.
    /// They are sent in the [`certificate_authorities`] extension of a
    /// [`CertificateRequest`] message.
    ///
    /// [Subjects]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.6
    /// [`CertificateRequest`]: https://datatracker.ietf.org/doc/html/rfc8446#section-4.3.2
    /// [`certificate_authorities`]: https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.4
    ///
    /// If the return value is empty, no CertificateRequest message will be sent.
    fn client_auth_root_subjects(&self) -> &[DistinguishedName];

    /// Verify the end-entity certificate `end_entity` is valid, acceptable,
    /// and chains to at least one of the trust anchors trusted by
    /// this verifier.
    ///
    /// `intermediates` contains the intermediate certificates the
    /// client sent along with the end-entity certificate; it is in the same
    /// order that the peer sent them and may be empty.
    ///
    /// Note that none of the certificates have been parsed yet, so it is the responsibility of
    /// the implementor to handle invalid data. It is recommended that the implementor returns
    /// an [InvalidCertificate] error with the [BadEncoding] variant when these cases are encountered.
    ///
    /// [InvalidCertificate]: Error#variant.InvalidCertificate
    /// [BadEncoding]: CertificateError#variant.BadEncoding
    fn verify_client_cert(
        &self,
        end_entity: &Certificate,
        intermediates: &[Certificate],
        now: SystemTime,
    ) -> Result<ClientCertVerified, Error>;

    /// Verify a signature allegedly by the given client certificate.
    ///
    /// `message` is not hashed, and needs hashing during the verification.
    /// The signature and algorithm are within `dss`.  `cert` contains the
    /// public key to use.
    ///
    /// `cert` has already been validated by [`ClientCertVerifier::verify_client_cert`].
    ///
    /// If and only if the signature is valid, return `Ok(HandshakeSignatureValid)`.
    /// Otherwise, return an error -- rustls will send an alert and abort the
    /// connection.
    ///
    /// This method is only called for TLS1.2 handshakes.  Note that, in TLS1.2,
    /// SignatureSchemes such as `SignatureScheme::ECDSA_NISTP256_SHA256` are not
    /// in fact bound to the specific curve implied in their name.
    ///
    /// This trait method has a default implementation that uses webpki to verify
    /// the signature.
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &Certificate,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_signed_struct(message, cert, dss)
    }

    /// Verify a signature allegedly by the given client certificate.
    ///
    /// This method is only called for TLS1.3 handshakes.
    ///
    /// This method is very similar to `verify_tls12_signature`, but note the
    /// tighter ECDSA SignatureScheme semantics in TLS 1.3. For example,
    /// `SignatureScheme::ECDSA_NISTP256_SHA256`
    /// must only validate signatures using public keys on the right curve --
    /// rustls does not enforce this requirement for you.
    ///
    /// This trait method has a default implementation that uses webpki to verify
    /// the signature.
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &Certificate,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13(message, cert, dss)
    }

    /// Return the list of SignatureSchemes that this verifier will handle,
    /// in `verify_tls12_signature` and `verify_tls13_signature` calls.
    ///
    /// This should be in priority order, with the most preferred first.
    ///
    /// This trait method has a default implementation that reflects the schemes
    /// supported by webpki.
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        WebPkiVerifier::verification_schemes()
    }
}

impl fmt::Debug for dyn ClientCertVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "dyn ClientCertVerifier")
    }
}

/// Verify that the end-entity certificate `end_entity` is a valid server cert
/// and chains to at least one of the [OwnedTrustAnchor] in the `roots` [RootCertStore].
///
/// `intermediates` contains all certificates other than `end_entity` that
/// were sent as part of the server's [Certificate] message. It is in the
/// same order that the server sent them and may be empty.
#[allow(dead_code)]
#[cfg_attr(not(feature = "dangerous_configuration"), allow(unreachable_pub))]
#[cfg_attr(docsrs, doc(cfg(feature = "dangerous_configuration")))]
pub fn verify_server_cert_signed_by_trust_anchor(
    cert: &ParsedCertificate,
    roots: &RootCertStore,
    intermediates: &[Certificate],
    now: SystemTime,
) -> Result<(), Error> {
    let chain = intermediate_chain(intermediates);
    let trust_roots = trust_roots(roots);
    let webpki_now = webpki::Time::try_from(now).map_err(|_| Error::FailedToGetCurrentTime)?;

    cert.0
        .verify_is_valid_tls_server_cert(
            SUPPORTED_SIG_ALGS,
            &webpki::TlsServerTrustAnchors(&trust_roots),
            &chain,
            webpki_now,
        )
        .map_err(pki_error)
        .map(|_| ())
}

/// Verify that the `end_entity` has a name or alternative name matching the `server_name`
/// note: this only verifies the name and should be used in conjuction with more verification
/// like [verify_server_cert_signed_by_trust_anchor]
#[cfg_attr(not(feature = "dangerous_configuration"), allow(unreachable_pub))]
#[cfg_attr(docsrs, doc(cfg(feature = "dangerous_configuration")))]
pub fn verify_server_name(cert: &ParsedCertificate, server_name: &ServerName) -> Result<(), Error> {
    match server_name {
        ServerName::DnsName(dns_name) => {
            // unlikely error because dns_name::DnsNameRef and webpki::DnsNameRef
            // should have the same encoding rules.
            let dns_name = webpki::DnsNameRef::try_from_ascii_str(dns_name.as_ref())
                .map_err(|_| Error::InvalidCertificate(CertificateError::BadEncoding))?;
            let name = webpki::SubjectNameRef::DnsName(dns_name);
            cert.0
                .verify_is_valid_for_subject_name(name)
                .map_err(pki_error)?;
        }
        ServerName::IpAddress(ip_addr) => {
            let ip_addr = webpki::IpAddr::from(*ip_addr);
            cert.0
                .verify_is_valid_for_subject_name(webpki::SubjectNameRef::IpAddress(
                    webpki::IpAddrRef::from(&ip_addr),
                ))
                .map_err(pki_error)?;
        }
    }
    Ok(())
}

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
        ocsp_response: &[u8],
        now: SystemTime,
    ) -> Result<ServerCertVerified, Error> {
        let cert = ParsedCertificate::try_from(end_entity)?;

        verify_server_cert_signed_by_trust_anchor(&cert, &self.roots, intermediates, now)?;

        if !ocsp_response.is_empty() {
            trace!("Unvalidated OCSP response: {:?}", ocsp_response.to_vec());
        }

        verify_server_name(&cert, server_name)?;
        Ok(ServerCertVerified::assertion())
    }
}

/// Default `ServerCertVerifier`, see the trait impl for more information.
#[allow(unreachable_pub)]
#[cfg_attr(docsrs, doc(cfg(feature = "dangerous_configuration")))]
pub struct WebPkiVerifier {
    roots: RootCertStore,
}

#[allow(unreachable_pub)]
impl WebPkiVerifier {
    /// Constructs a new `WebPkiVerifier`.
    ///
    /// `roots` is the set of trust anchors to trust for issuing server certs.
    pub fn new(roots: RootCertStore) -> Self {
        Self { roots }
    }

    /// Returns the signature verification methods supported by
    /// webpki.
    pub fn verification_schemes() -> Vec<SignatureScheme> {
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
}

fn intermediate_chain(intermediates: &[Certificate]) -> Vec<&[u8]> {
    intermediates
        .iter()
        .map(|cert| cert.0.as_ref())
        .collect()
}

fn trust_roots(roots: &RootCertStore) -> Vec<webpki::TrustAnchor> {
    roots
        .roots
        .iter()
        .map(OwnedTrustAnchor::to_trust_anchor)
        .collect()
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
        let cert = ParsedCertificate::try_from(end_entity)?;
        let chain = intermediate_chain(intermediates);
        let trust_roots = trust_roots(&self.roots);
        let now = webpki::Time::try_from(now).map_err(|_| Error::FailedToGetCurrentTime)?;

        cert.0
            .verify_is_valid_tls_client_cert(
                SUPPORTED_SIG_ALGS,
                &webpki::TlsClientTrustAnchors(&trust_roots),
                &chain,
                now,
            )
            .map_err(pki_error)
            .map(|_| ClientCertVerified::assertion())
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
}

pub(crate) fn pki_error(error: webpki::Error) -> Error {
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

/// Turns off client authentication.
pub struct NoClientAuth;

impl NoClientAuth {
    /// Construct a [`NoClientAuth`], wrap it in an [`Arc`] and coerce it to
    /// `dyn ClientCertVerifier`.
    #[inline(always)]
    pub fn boxed() -> Arc<dyn ClientCertVerifier> {
        // This function is needed because `ClientCertVerifier` is only reachable if the
        // `dangerous_configuration` feature is enabled, which makes coercing hard to outside users
        Arc::new(Self)
    }
}

impl ClientCertVerifier for NoClientAuth {
    fn offer_client_auth(&self) -> bool {
        false
    }

    fn client_auth_root_subjects(&self) -> &[DistinguishedName] {
        unimplemented!();
    }

    fn verify_client_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _now: SystemTime,
    ) -> Result<ClientCertVerified, Error> {
        unimplemented!();
    }
}

/// This type combines a [`SignatureScheme`] and a signature payload produced with that scheme.
#[derive(Debug, Clone)]
pub struct DigitallySignedStruct {
    /// The [`SignatureScheme`] used to produce the signature.
    pub scheme: SignatureScheme,
    sig: PayloadU16,
}

impl DigitallySignedStruct {
    pub(crate) fn new(scheme: SignatureScheme, sig: Vec<u8>) -> Self {
        Self {
            scheme,
            sig: PayloadU16::new(sig),
        }
    }

    /// Get the signature.
    pub fn signature(&self) -> &[u8] {
        &self.sig.0
    }
}

impl Codec for DigitallySignedStruct {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.scheme.encode(bytes);
        self.sig.encode(bytes);
    }

    fn read(r: &mut Reader) -> Result<Self, InvalidMessage> {
        let scheme = SignatureScheme::read(r)?;
        let sig = PayloadU16::read(r)?;

        Ok(Self { scheme, sig })
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

/// Constructs the signature message specified in section 4.4.3 of RFC8446.
pub(crate) fn construct_tls13_client_verify_message(handshake_hash: &Digest) -> Vec<u8> {
    construct_tls13_verify_message(handshake_hash, b"TLS 1.3, client CertificateVerify\x00")
}

/// Constructs the signature message specified in section 4.4.3 of RFC8446.
pub(crate) fn construct_tls13_server_verify_message(handshake_hash: &Digest) -> Vec<u8> {
    construct_tls13_verify_message(handshake_hash, b"TLS 1.3, server CertificateVerify\x00")
}

fn construct_tls13_verify_message(
    handshake_hash: &Digest,
    context_string_with_0: &[u8],
) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.resize(64, 0x20u8);
    msg.extend_from_slice(context_string_with_0);
    msg.extend_from_slice(handshake_hash.as_ref());
    msg
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assertions_are_debug() {
        assert_eq!(
            format!("{:?}", ClientCertVerified::assertion()),
            "ClientCertVerified(())"
        );
        assert_eq!(
            format!("{:?}", HandshakeSignatureValid::assertion()),
            "HandshakeSignatureValid(())"
        );
        assert_eq!(
            format!("{:?}", FinishedMessageVerified::assertion()),
            "FinishedMessageVerified(())"
        );
        assert_eq!(
            format!("{:?}", ServerCertVerified::assertion()),
            "ServerCertVerified(())"
        );
    }
}
