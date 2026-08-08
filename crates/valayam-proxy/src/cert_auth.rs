use rcgen::{BasicConstraints, Certificate, CertificateParams, IsCa, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use time::{Duration, OffsetDateTime};
use tokio_rustls::TlsAcceptor;

pub struct CertificateAuthority {
    ca_cert: Certificate,
}

impl CertificateAuthority {
    pub fn new() -> Result<Self, anyhow::Error> {
        let home_dir = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        let valayam_dir = home_dir.join(".valayam");

        if !valayam_dir.exists() {
            fs::create_dir_all(&valayam_dir)?;
        }

        let cert_path = valayam_dir.join("ca.crt");
        let key_path = valayam_dir.join("ca.key");

        println!("[*] Generating new Dynamic Root CA for TLS Interception...");
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Valayam MITM Root CA");
        params
            .distinguished_name
            .push(rcgen::DnType::OrganizationName, "Valayam Security");

        params.not_before = OffsetDateTime::now_utc();
        params.not_after = OffsetDateTime::now_utc() + Duration::days(365);

        let key_pair = KeyPair::generate(&rcgen::PKCS_ECDSA_P256_SHA256)?;
        let ca_cert = Certificate::from_params(params)?;

        let cert_pem = ca_cert.serialize_pem()?;
        let key_pem = key_pair.serialize_pem();

        fs::write(&cert_path, cert_pem)?;
        fs::write(&key_path, key_pem)?;

        println!("[+] Root CA saved to: {}", cert_path.display());
        println!("[!] IMPORTANT: To intercept HTTPS traffic without browser warnings, install this CA in your OS/Browser trust store.");

        Ok(Self { ca_cert })
    }

    pub fn gen_acceptor_for_domain(&self, domain: &str) -> Result<TlsAcceptor, anyhow::Error> {
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, domain);
        params.subject_alt_names = vec![rcgen::SanType::DnsName(domain.to_string())];

        params.not_before = OffsetDateTime::now_utc() - Duration::days(1);
        params.not_after = OffsetDateTime::now_utc() + Duration::days(7);

        let cert = Certificate::from_params(params)?;

        let cert_pem = cert.serialize_pem_with_signer(&self.ca_cert)?;
        let key_pem = cert.serialize_private_key_pem();

        let rustls_cert: CertificateDer<'static> = rustls_pemfile::certs(&mut cert_pem.as_bytes())
            .filter_map(Result::ok)
            .next()
            .ok_or_else(|| anyhow::anyhow!("failed to parse generated leaf certificate PEM"))?
            .into_owned();

        let rustls_key: PrivateKeyDer<'static> =
            rustls_pemfile::pkcs8_private_keys(&mut key_pem.as_bytes())
                .filter_map(Result::ok)
                .next()
                .ok_or_else(|| anyhow::anyhow!("failed to parse generated leaf key PEM"))?
                .into();

        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![rustls_cert], rustls_key)?;

        Ok(TlsAcceptor::from(Arc::new(server_config)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cert_params_creation() {
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Test CA");
        let cert = Certificate::from_params(params);
        assert!(cert.is_ok());

        let cert = cert.unwrap();
        let cert_pem = cert.serialize_pem();
        assert!(cert_pem.is_ok());
        assert!(cert_pem.unwrap().contains("BEGIN CERTIFICATE"));
    }
}
