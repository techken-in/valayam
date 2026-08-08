//! Cryptographic primitives for Valayam plugin signing and verification.
//!
//! Uses Ed25519 (EdDSA) for digital signatures. The `PluginCrypto` struct
//! provides key generation, signing, and verification with a clear API.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;

pub struct PluginCrypto;

impl PluginCrypto {
    /// Generates a new ED25519 keypair, returning (private_key_bytes, public_key_bytes)
    pub fn generate_keypair() -> ([u8; 32], [u8; 32]) {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();
        (signing_key.to_bytes(), verifying_key.to_bytes())
    }

    /// Signs a payload and returns the signature bytes
    pub fn sign(private_key: &[u8; 32], message: &[u8]) -> anyhow::Result<[u8; 64]> {
        let signing_key = SigningKey::from_bytes(private_key);
        let signature = signing_key.sign(message);
        Ok(signature.to_bytes())
    }

    /// Verifies a signature for a payload against a public key
    pub fn verify(
        public_key: &[u8; 32],
        message: &[u8],
        signature_bytes: &[u8; 64],
    ) -> anyhow::Result<bool> {
        let verifying_key = VerifyingKey::from_bytes(public_key)
            .map_err(|e| anyhow::anyhow!("Invalid public key format: {}", e))?;
        let signature = Signature::from_bytes(signature_bytes);

        match verifying_key.verify(message, &signature) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_keypair_returns_32_byte_keys() {
        let (private, public) = PluginCrypto::generate_keypair();
        assert_eq!(private.len(), 32);
        assert_eq!(public.len(), 32);
        assert_ne!(private, public);
    }

    #[test]
    fn test_sign_and_verify_roundtrip() -> anyhow::Result<()> {
        let (private, public) = PluginCrypto::generate_keypair();
        let message = b"test message to sign";
        let signature = PluginCrypto::sign(&private, message)?;
        assert_eq!(signature.len(), 64);

        let valid = PluginCrypto::verify(&public, message, &signature)?;
        assert!(valid);
        Ok(())
    }

    #[test]
    fn test_verify_rejects_tampered_message() -> anyhow::Result<()> {
        let (private, public) = PluginCrypto::generate_keypair();
        let signature = PluginCrypto::sign(&private, b"original message")?;
        let valid = PluginCrypto::verify(&public, b"tampered message", &signature)?;
        assert!(!valid);
        Ok(())
    }

    #[test]
    fn test_verify_rejects_wrong_key() -> anyhow::Result<()> {
        let (private_a, _public_a) = PluginCrypto::generate_keypair();
        let (_private_b, public_b) = PluginCrypto::generate_keypair();
        let signature = PluginCrypto::sign(&private_a, b"test message")?;
        let valid = PluginCrypto::verify(&public_b, b"test message", &signature)?;
        assert!(!valid);
        Ok(())
    }

    #[test]
    fn test_generate_unique_keys() {
        let kp1 = PluginCrypto::generate_keypair();
        let kp2 = PluginCrypto::generate_keypair();
        let kp3 = PluginCrypto::generate_keypair();
        assert_ne!(kp1, kp2);
        assert_ne!(kp2, kp3);
        assert_ne!(kp1, kp3);
    }

    #[test]
    fn test_sign_empty_message() -> anyhow::Result<()> {
        let (private, public) = PluginCrypto::generate_keypair();
        let signature = PluginCrypto::sign(&private, b"")?;
        let valid = PluginCrypto::verify(&public, b"", &signature)?;
        assert!(valid);
        Ok(())
    }

    #[test]
    fn test_sign_and_verify_large_message() -> anyhow::Result<()> {
        let (private, public) = PluginCrypto::generate_keypair();
        let large_msg = vec![0xABu8; 10000];
        let sig = PluginCrypto::sign(&private, &large_msg)?;
        let valid = PluginCrypto::verify(&public, &large_msg, &sig)?;
        assert!(valid);
        Ok(())
    }
}
