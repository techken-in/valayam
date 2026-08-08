//! TLS fingerprinting evasion utilities for JA3/JA4 spoofing
use rustls::client::danger::{ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{ServerName, UnixTime};
use rustls::SignatureScheme;

/// A TLS certificate verifier that accepts all certificates.
/// Used for inspection/diagnostic purposes where we don't need to validate the server identity.
#[derive(Debug)]
pub struct NoCertVerification;

impl NoCertVerification {
    /// Creates a new `NoCertVerification` instance.
    pub fn new() -> Self {
        Self
    }
}

impl ServerCertVerifier for NoCertVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

impl Default for NoCertVerification {
    fn default() -> Self {
        Self::new()
    }
}

/// JA3/JA4 spoofer for TLS fingerprint evasion
///
/// This module provides utilities to modify TLS client hello messages
/// to mimic common browsers and evade WAF/detection systems that rely on TLS fingerprinting.
#[derive(Clone)]
pub struct Ja3Ja4Spoofer {
    /// Profile to mimic (chrome, firefox, safari, edge, etc.)
    profile: Ja3Ja4Profile,
    /// Custom JA3 string to use (if Some, overrides profile )
    custom_ja3: Option<String>,
    /// Custom JA4 string to use ( if Some, overrides profile )
    custom_ja4: Option<String>,
}

impl Ja3Ja4Spoofer {
    /// Create a new JA3/JA4 spoofer with the specified profile
    pub fn new(profile: Ja3Ja4Profile) -> Self {
        Self {
            profile,
            custom_ja3: None,
            custom_ja4: None,
        }
    }

    /// Set a custom JA3 string to use
    pub fn with_ja3(mut self, ja3: impl Into<String>) -> Self {
        self.custom_ja3 = Some(ja3.into());
        self
    }

    /// Set a custom JA4 string to use
    pub fn with_ja4(mut self, ja4: impl Into<String>) -> Self {
        self.custom_ja4 = Some(ja4.into());
        self
    }

    /// Get a custom CryptoProvider tailored to the spoofing profile
    pub fn get_provider(&self) -> rustls::crypto::CryptoProvider {
        match self.profile {
            Ja3Ja4Profile::Chrome => self.chrome_provider(),
            Ja3Ja4Profile::Firefox => self.firefox_provider(),
            Ja3Ja4Profile::Safari => self.safari_provider(),
            Ja3Ja4Profile::Edge => self.edge_provider(),
            Ja3Ja4Profile::Random => self.random_provider(),
        }
    }

    /// Chrome-like TLS provider
    fn chrome_provider(&self) -> rustls::crypto::CryptoProvider {
        tracing::debug!("Applying Chrome TLS profile");
        let mut provider = rustls::crypto::ring::default_provider();

        // Chrome typically prioritizes GREASE, AES_128_GCM, CHACHA20, AES_256_GCM
        // We rearrange the default provider's cipher suites to match Chrome's preference
        let suites = &provider.cipher_suites;
        let mut new_suites = Vec::new();

        // Note: rustls doesn't support GREASE natively in configuration, but we can reorder the real ones.
        // Chrome preference: TLS13_AES_128_GCM, TLS13_CHACHA20, TLS13_AES_256_GCM
        if let Some(c) = suites
            .iter()
            .find(|s| s.suite() == rustls::CipherSuite::TLS13_AES_128_GCM_SHA256)
        {
            new_suites.push(*c);
        }
        if let Some(c) = suites
            .iter()
            .find(|s| s.suite() == rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256)
        {
            new_suites.push(*c);
        }
        if let Some(c) = suites
            .iter()
            .find(|s| s.suite() == rustls::CipherSuite::TLS13_AES_256_GCM_SHA384)
        {
            new_suites.push(*c);
        }
        // TLS 1.2
        if let Some(c) = suites
            .iter()
            .find(|s| s.suite() == rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
        {
            new_suites.push(*c);
        }
        if let Some(c) = suites
            .iter()
            .find(|s| s.suite() == rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
        {
            new_suites.push(*c);
        }
        if let Some(c) = suites.iter().find(|s| {
            s.suite() == rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
        }) {
            new_suites.push(*c);
        }
        if let Some(c) = suites
            .iter()
            .find(|s| s.suite() == rustls::CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256)
        {
            new_suites.push(*c);
        }
        if let Some(c) = suites
            .iter()
            .find(|s| s.suite() == rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384)
        {
            new_suites.push(*c);
        }
        if let Some(c) = suites
            .iter()
            .find(|s| s.suite() == rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384)
        {
            new_suites.push(*c);
        }

        provider.cipher_suites = new_suites;
        provider
    }

    /// Firefox-like TLS provider
    fn firefox_provider(&self) -> rustls::crypto::CryptoProvider {
        tracing::debug!("Applying Firefox TLS profile");
        let mut provider = rustls::crypto::ring::default_provider();

        // Firefox prioritizes AES_128_GCM, CHACHA20, AES_256_GCM just like Chrome, but sometimes with slight variation in TLS 1.2
        let suites = &provider.cipher_suites;
        let mut new_suites = Vec::new();

        if let Some(c) = suites
            .iter()
            .find(|s| s.suite() == rustls::CipherSuite::TLS13_AES_128_GCM_SHA256)
        {
            new_suites.push(*c);
        }
        if let Some(c) = suites
            .iter()
            .find(|s| s.suite() == rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256)
        {
            new_suites.push(*c);
        }
        if let Some(c) = suites
            .iter()
            .find(|s| s.suite() == rustls::CipherSuite::TLS13_AES_256_GCM_SHA384)
        {
            new_suites.push(*c);
        }

        if let Some(c) = suites
            .iter()
            .find(|s| s.suite() == rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
        {
            new_suites.push(*c);
        }
        if let Some(c) = suites
            .iter()
            .find(|s| s.suite() == rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
        {
            new_suites.push(*c);
        }
        if let Some(c) = suites.iter().find(|s| {
            s.suite() == rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
        }) {
            new_suites.push(*c);
        }
        if let Some(c) = suites
            .iter()
            .find(|s| s.suite() == rustls::CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256)
        {
            new_suites.push(*c);
        }
        if let Some(c) = suites
            .iter()
            .find(|s| s.suite() == rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384)
        {
            new_suites.push(*c);
        }
        if let Some(c) = suites
            .iter()
            .find(|s| s.suite() == rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384)
        {
            new_suites.push(*c);
        }

        provider.cipher_suites = new_suites;
        provider
    }

    /// Safari-like TLS provider
    fn safari_provider(&self) -> rustls::crypto::CryptoProvider {
        tracing::debug!("Applying Safari TLS profile");
        let mut provider = rustls::crypto::ring::default_provider();

        // Safari (macOS/iOS) heavily prioritizes CHACHA20 over AES
        let suites = &provider.cipher_suites;
        let mut new_suites = Vec::new();

        if let Some(c) = suites
            .iter()
            .find(|s| s.suite() == rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256)
        {
            new_suites.push(*c);
        }
        if let Some(c) = suites
            .iter()
            .find(|s| s.suite() == rustls::CipherSuite::TLS13_AES_128_GCM_SHA256)
        {
            new_suites.push(*c);
        }
        if let Some(c) = suites
            .iter()
            .find(|s| s.suite() == rustls::CipherSuite::TLS13_AES_256_GCM_SHA384)
        {
            new_suites.push(*c);
        }

        if let Some(c) = suites.iter().find(|s| {
            s.suite() == rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
        }) {
            new_suites.push(*c);
        }
        if let Some(c) = suites
            .iter()
            .find(|s| s.suite() == rustls::CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256)
        {
            new_suites.push(*c);
        }
        if let Some(c) = suites
            .iter()
            .find(|s| s.suite() == rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
        {
            new_suites.push(*c);
        }
        if let Some(c) = suites
            .iter()
            .find(|s| s.suite() == rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
        {
            new_suites.push(*c);
        }
        if let Some(c) = suites
            .iter()
            .find(|s| s.suite() == rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384)
        {
            new_suites.push(*c);
        }
        if let Some(c) = suites
            .iter()
            .find(|s| s.suite() == rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384)
        {
            new_suites.push(*c);
        }

        provider.cipher_suites = new_suites;
        provider
    }

    /// Edge-like TLS provider
    fn edge_provider(&self) -> rustls::crypto::CryptoProvider {
        tracing::debug!("Applying Edge TLS profile");
        // Edge is Chromium based, use same as Chrome
        self.chrome_provider()
    }

    /// Apply a random profile to avoid fingerprinting
    fn random_provider(&self) -> rustls::crypto::CryptoProvider {
        use rand::seq::SliceRandom;
        use rand::thread_rng;

        let profiles = [
            Ja3Ja4Profile::Chrome,
            Ja3Ja4Profile::Firefox,
            Ja3Ja4Profile::Safari,
            Ja3Ja4Profile::Edge,
        ];

        let mut rng = thread_rng();
        let chosen = profiles.choose(&mut rng).unwrap_or(&Ja3Ja4Profile::Chrome);

        match chosen {
            Ja3Ja4Profile::Chrome => self.chrome_provider(),
            Ja3Ja4Profile::Firefox => self.firefox_provider(),
            Ja3Ja4Profile::Safari => self.safari_provider(),
            Ja3Ja4Profile::Edge => self.edge_provider(),
            _ => self.chrome_provider(),
        }
    }
}

/// Available JA3/JA4 profiles for spoofing
#[derive(Debug, Clone, Copy)]
pub enum Ja3Ja4Profile {
    Chrome,
    Firefox,
    Safari,
    Edge,
    Random,
}

/// TLS configuration wrapper that applies JA3/JA4 spoofing
pub struct TlsConfig {
    /// JA3/JA4 spoofer for fingerprint evasion
    spoofer: Option<Ja3Ja4Spoofer>,
}

impl TlsConfig {
    /// Create a new TLS config with optional JA3/JA4 spoofing
    pub fn new_with_spoofing(
        profile: Option<Ja3Ja4Profile>,
    ) -> Result<Self, valayam_models::error::ScannerError> {
        // Install crypto provider if not already done
        let _ = rustls::crypto::ring::default_provider().install_default();

        // Create spoofer if profile is specified
        let spoofer = profile.map(Ja3Ja4Spoofer::new);

        Ok(Self { spoofer })
    }

    /// Build a ClientConfig with optional JA3/JA4 spoofing
    pub fn build(&self) -> Result<rustls::ClientConfig, valayam_models::error::ScannerError> {
        let provider = if let Some(ref spoofer) = self.spoofer {
            spoofer.get_provider()
        } else {
            rustls::crypto::ring::default_provider()
        };

        let config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(provider))
            .with_safe_default_protocol_versions()
            .map_err(|e| valayam_models::error::ScannerError::ConfigurationError(e.to_string()))?
            .dangerous()
            .with_custom_certificate_verifier(std::sync::Arc::new(NoCertVerification::new()))
            .with_no_client_auth();

        Ok(config)
    }

    /// Enable JA3/JA4 spoofing with a specific profile
    pub fn with_spoofing(mut self, profile: Ja3Ja4Profile) -> Self {
        self.spoofer = Some(Ja3Ja4Spoofer::new(profile));
        self
    }

    /// Disable JA3/JA4 spoofing
    pub fn without_spoofing(mut self) -> Self {
        self.spoofer = None;
        self
    }
}

/// Build a permissive TLS ClientConfig that accepts all certificates
pub fn build_permissive_tls_config() -> rustls::ClientConfig {
    let _ = rustls::crypto::ring::default_provider().install_default();

    rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(NoCertVerification::new()))
        .with_no_client_auth()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::ClientConfig;

    #[test]
    fn test_tls_config_creation() {
        let config = TlsConfig::new_with_spoofing(None).expect("Should create config");
        let client_config = config.build().expect("Should build config");
        // Verify it's a valid config by checking it has the right type
        let _: ClientConfig = client_config;
    }

    #[test]
    fn test_tls_config_with_spoofing() {
        let config = TlsConfig::new_with_spoofing(Some(Ja3Ja4Profile::Chrome))
            .expect("Should create config with spoofing");
        let client_config = config.build().expect("Should build config");
        let _: ClientConfig = client_config;
    }

    #[test]
    fn test_no_cert_verification() {
        let verifier = NoCertVerification::new();
        let schemes = verifier.supported_verify_schemes();
        assert!(!schemes.is_empty());
    }

    #[test]
    fn test_permissive_config() {
        let config = build_permissive_tls_config();
        let _: ClientConfig = config;
    }
}
