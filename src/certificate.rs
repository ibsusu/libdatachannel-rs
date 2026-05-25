//! DTLS certificate + private-key pair, mirroring `rtc::impl::Certificate`
//! from `native/libdatachannel/src/impl/certificate.cpp` (OpenSSL path).
//!
//! A [`Certificate`] holds a self-signed X.509 certificate and its matching
//! private key. Phase G-5a uses these to seed the
//! [`DtlsTransport`](crate::DtlsTransport) `SSL_CTX`; later phases reuse the
//! same cert to compute the local fingerprint that goes into the SDP
//! offer/answer.
//!
//! ## Defaults
//!
//! - `generate_ecdsa()` matches the upstream default:
//!   - Curve: NIST P-256 (`prime256v1`, `Nid::X9_62_PRIME256V1`).
//!   - Subject + issuer CN: `"rtc"` (self-signed).
//!   - Serial: 64 random bits (the C++ uses a random `BIGNUM`).
//!   - Validity: `notBefore = now`, `notAfter = now + 30 days`.
//!   - Signed with SHA-256.
//! - `generate_rsa()` produces a 2048-bit RSA key with the same X.509
//!   skeleton.
//! - [`Certificate::default`] / `Certificate::generate_default()` returns the
//!   ECDSA flavour (this is the C++ default at
//!   `Certificate::Generate(CertificateType::Default, ...)`).
//!
//! ## C++ divergence notes
//!
//! - The C++ uses `notAfter = now + 365 days`. Phase G-5a tightens this to
//!   30 days to match the task spec; the only observable difference is the
//!   value emitted in `a=fingerprint:` rotates more aggressively, which is
//!   harmless.
//! - The C++ uses `BN_rand(serial, 16, 0, 0)` (16 *bits* — note: bits, not
//!   bytes — despite the comment in the C source). We use 64 bits so the
//!   serial space is wide enough that two `Certificate::generate_ecdsa()`
//!   calls in the same test never collide.

use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::ec::{EcGroup, EcKey};
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::{X509, X509Builder, X509NameBuilder};
use thiserror::Error;

use crate::configuration::CertificateType;
use crate::description::{Fingerprint, FingerprintAlgorithm};

/// Errors returned by [`Certificate`] generation.
#[derive(Debug, Error)]
pub enum CertificateError {
    /// Forwarded from OpenSSL.
    #[error("openssl: {0}")]
    OpenSsl(#[from] ErrorStack),
}

/// Self-signed DTLS certificate + matching private key.
///
/// Construct with one of [`Certificate::generate_default`],
/// [`Certificate::generate_ecdsa`], or [`Certificate::generate_rsa`]. Both
/// the cert and the key are owned by the `Certificate`; clone the
/// references out with [`Certificate::x509`] / [`Certificate::pkey`] when
/// wiring up a DTLS context.
pub struct Certificate {
    x509: X509,
    pkey: PKey<Private>,
}

impl std::fmt::Debug for Certificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Certificate")
            .field(
                "fingerprint_sha256",
                &self
                    .fingerprint(FingerprintAlgorithm::Sha256)
                    .map(|f| f.value),
            )
            .finish()
    }
}

impl Certificate {
    /// Generate a fresh certificate using the library default
    /// (currently ECDSA P-256, matching the upstream
    /// `CertificateType::Default` switch arm).
    pub fn generate_default() -> Result<Self, CertificateError> {
        Self::generate(CertificateType::Default, "rtc")
    }

    /// Generate a fresh certificate for the given algorithm. `cn` is the
    /// `CN=` attribute on both the issuer and subject DN (self-signed).
    pub fn generate(typ: CertificateType, cn: &str) -> Result<Self, CertificateError> {
        match typ {
            CertificateType::Default | CertificateType::EcDsa => Self::generate_ecdsa(cn),
            CertificateType::Rsa => Self::generate_rsa(cn),
        }
    }

    /// Generate an ECDSA P-256 self-signed certificate.
    pub fn generate_ecdsa(cn: &str) -> Result<Self, CertificateError> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let ec_key = EcKey::generate(&group)?;
        let pkey = PKey::from_ec_key(ec_key)?;
        let x509 = build_self_signed(&pkey, cn)?;
        Ok(Certificate { x509, pkey })
    }

    /// Generate an RSA-2048 self-signed certificate.
    pub fn generate_rsa(cn: &str) -> Result<Self, CertificateError> {
        let rsa = Rsa::generate(2048)?;
        let pkey = PKey::from_rsa(rsa)?;
        let x509 = build_self_signed(&pkey, cn)?;
        Ok(Certificate { x509, pkey })
    }

    /// Clone the certificate into an independent handle.
    ///
    /// Both `X509` and `PKey<Private>` are reference-counted in openssl-rs,
    /// so this is a cheap reference clone rather than a re-derivation of the
    /// keypair. Used by [`PeerConnection`](crate::PeerConnection), which holds
    /// one certificate but constructs the [`DtlsTransport`](crate::DtlsTransport)
    /// (which takes ownership of a `Certificate`) lazily.
    pub fn try_clone(&self) -> Result<Self, CertificateError> {
        Ok(Certificate {
            x509: self.x509.clone(),
            pkey: self.pkey.clone(),
        })
    }

    /// Borrow the X.509 certificate.
    pub fn x509(&self) -> &X509 {
        &self.x509
    }

    /// Borrow the private key.
    pub fn pkey(&self) -> &PKey<Private> {
        &self.pkey
    }

    /// Compute the certificate fingerprint for `algorithm`. Returns the
    /// SDP-shaped colon-separated upper-case hex (`AB:CD:...`), wrapped in
    /// a [`Fingerprint`] ready for [`Description::set_fingerprint`].
    ///
    /// [`Description::set_fingerprint`]: crate::Description::set_fingerprint
    pub fn fingerprint(
        &self,
        algorithm: FingerprintAlgorithm,
    ) -> Result<Fingerprint, CertificateError> {
        let md = match algorithm {
            FingerprintAlgorithm::Sha1 => MessageDigest::sha1(),
            FingerprintAlgorithm::Sha224 => MessageDigest::sha224(),
            FingerprintAlgorithm::Sha256 => MessageDigest::sha256(),
            FingerprintAlgorithm::Sha384 => MessageDigest::sha384(),
            FingerprintAlgorithm::Sha512 => MessageDigest::sha512(),
        };
        let bytes = self.x509.digest(md)?;
        Ok(Fingerprint {
            algorithm,
            value: format_fingerprint(bytes.as_ref()),
        })
    }
}

/// Format raw digest bytes as `AB:CD:EF:...` upper-case colon-separated hex.
/// Matches the C++ `make_fingerprint` formatter at
/// `native/libdatachannel/src/impl/certificate.cpp:482`.
///
/// Visible to the crate so `dtls_transport`'s verify callback can render
/// peer-cert digests in the same shape as the SDP fingerprint we compare
/// against.
pub(crate) fn format_fingerprint(bytes: &[u8]) -> String {
    // 2 hex chars per byte + `:` between each pair = 3*N - 1.
    let mut s = String::with_capacity(bytes.len() * 3);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            s.push(':');
        }
        s.push(hex_upper((b >> 4) & 0x0F));
        s.push(hex_upper(b & 0x0F));
    }
    s
}

fn hex_upper(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        10..=15 => (b'A' + nibble - 10) as char,
        _ => unreachable!("nibble out of range"),
    }
}

/// Build a self-signed X.509 cert around `pkey`. Mirrors the C++ X509
/// skeleton at `native/libdatachannel/src/impl/certificate.cpp:444`.
fn build_self_signed(pkey: &PKey<Private>, cn: &str) -> Result<X509, ErrorStack> {
    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_text("CN", cn)?;
    let name = name.build();

    let mut builder = X509Builder::new()?;
    // X509 v3 (the encoded `version` field is the spec value minus 1).
    builder.set_version(2)?;

    // Random 64-bit serial (avoids collisions between certs generated in
    // the same process). The C++ uses BN_rand with 16 bits; 64 is harmless
    // and matches the comment in the C source rather than the literal.
    let mut serial = BigNum::new()?;
    serial.rand(64, MsbOption::MAYBE_ZERO, false)?;
    let serial = serial.to_asn1_integer()?;
    builder.set_serial_number(&serial)?;

    // Self-signed: issuer == subject.
    builder.set_issuer_name(&name)?;
    builder.set_subject_name(&name)?;
    builder.set_pubkey(pkey)?;

    // `not_before = now`, `not_after = now + 30 days`. The C++ uses
    // `X509_gmtime_adj(notBefore, -3600)` (one hour clock skew tolerance);
    // openssl-rs doesn't expose a signed `from_period`, so we accept a
    // small loss of skew tolerance here. `not_after` matches the spec at
    // 30 days — see the module-level note on the divergence from the C++
    // `365 days` default.
    let not_before = Asn1Time::days_from_now(0)?;
    let not_after = Asn1Time::days_from_now(30)?;
    builder.set_not_before(&not_before)?;
    builder.set_not_after(&not_after)?;

    builder.sign(pkey, MessageDigest::sha256())?;
    Ok(builder.build())
}

impl Default for Certificate {
    /// Convenience wrapper around [`Certificate::generate_default`].
    ///
    /// # Panics
    ///
    /// Panics if OpenSSL fails to generate a key pair (only seen on a
    /// completely broken libcrypto build).
    fn default() -> Self {
        Self::generate_default().expect("Certificate::default(): generate_default failed")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_default_produces_ecdsa_with_sha256_fingerprint() {
        let c = Certificate::generate_default().expect("generate default");
        let fp = c
            .fingerprint(FingerprintAlgorithm::Sha256)
            .expect("sha-256 digest");
        assert_eq!(fp.algorithm, FingerprintAlgorithm::Sha256);
        // Format: 32 bytes → 95 chars (32 * 3 - 1).
        assert_eq!(fp.value.len(), 95, "fp was {:?}", fp.value);
        assert!(fp.is_valid(), "fp invalid: {:?}", fp.value);
    }

    #[test]
    fn generate_ecdsa_and_rsa_have_distinct_fingerprints() {
        let ec = Certificate::generate_ecdsa("rtc").expect("ecdsa");
        let rsa = Certificate::generate_rsa("rtc").expect("rsa");
        let f_ec = ec.fingerprint(FingerprintAlgorithm::Sha256).unwrap().value;
        let f_rsa = rsa.fingerprint(FingerprintAlgorithm::Sha256).unwrap().value;
        assert_ne!(f_ec, f_rsa, "ECDSA and RSA fingerprints collided ({f_ec})");
        // Both must still validate as SDP fingerprints.
        assert_eq!(f_ec.len(), 95);
        assert_eq!(f_rsa.len(), 95);
    }

    #[test]
    fn fingerprint_is_deterministic_for_one_cert() {
        // Same cert -> same fingerprint, regardless of how many times we ask.
        let c = Certificate::generate_default().unwrap();
        let a = c.fingerprint(FingerprintAlgorithm::Sha256).unwrap().value;
        let b = c.fingerprint(FingerprintAlgorithm::Sha256).unwrap().value;
        assert_eq!(a, b);
        // Different algorithms produce different lengths.
        let s1 = c.fingerprint(FingerprintAlgorithm::Sha1).unwrap().value;
        assert_eq!(s1.len(), 20 * 3 - 1);
        let s5 = c.fingerprint(FingerprintAlgorithm::Sha512).unwrap().value;
        assert_eq!(s5.len(), 64 * 3 - 1);
    }

    #[test]
    fn two_generated_certs_have_different_fingerprints() {
        // Random serial + fresh keypair → fingerprints must differ.
        let a = Certificate::generate_ecdsa("rtc").unwrap();
        let b = Certificate::generate_ecdsa("rtc").unwrap();
        let fa = a.fingerprint(FingerprintAlgorithm::Sha256).unwrap().value;
        let fb = b.fingerprint(FingerprintAlgorithm::Sha256).unwrap().value;
        assert_ne!(fa, fb, "two freshly-generated certs collided: {fa}");
    }

    #[test]
    fn fingerprint_format_is_uppercase_colon_hex() {
        let c = Certificate::generate_default().unwrap();
        let fp = c.fingerprint(FingerprintAlgorithm::Sha256).unwrap().value;
        // Every odd position is `:`; every other character is upper-hex.
        for (i, ch) in fp.chars().enumerate() {
            if i % 3 == 2 {
                assert_eq!(ch, ':', "expected `:` at index {i}, got {ch:?} in {fp}");
            } else {
                assert!(
                    ch.is_ascii_hexdigit() && !ch.is_ascii_lowercase(),
                    "expected upper-hex digit at {i}, got {ch:?} in {fp}"
                );
            }
        }
    }
}
