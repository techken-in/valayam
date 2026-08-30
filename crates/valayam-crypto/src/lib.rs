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

    /// Encodes a 32-byte private key into standard PEM format
    pub fn encode_private_key_pem(key: &[u8; 32]) -> String {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(key);
        format!("-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n", b64)
    }

    /// Encodes a 32-byte public key into standard PEM format
    pub fn encode_public_key_pem(key: &[u8; 32]) -> String {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(key);
        format!("-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n", b64)
    }

    /// Flexible key decoder: parses PEM, Hex (64 chars), Base64, or raw 32-byte binary
    pub fn decode_key_bytes(input: &[u8]) -> anyhow::Result<[u8; 32]> {
        if input.len() == 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(input);
            return Ok(key);
        }

        let text = std::str::from_utf8(input)
            .map_err(|_| anyhow::anyhow!("Invalid key data (expected 32-byte binary or valid PEM/Hex)"))?;
        let text_trimmed = text.trim();

        // Check PEM format
        if text_trimmed.starts_with("-----BEGIN") {
            let lines: Vec<&str> = text_trimmed
                .lines()
                .filter(|line| !line.trim().starts_with("-----"))
                .collect();
            let b64_clean = lines.join("").replace(['\r', '\n', ' '], "");
            use base64::Engine;
            let bytes = base64::engine::general_purpose::STANDARD.decode(b64_clean)
                .map_err(|e| anyhow::anyhow!("Failed to decode base64 from PEM: {}", e))?;
            if bytes.len() == 32 {
                let mut key = [0u8; 32];
                key.copy_from_slice(&bytes);
                return Ok(key);
            } else if bytes.len() > 32 {
                let mut key = [0u8; 32];
                key.copy_from_slice(&bytes[bytes.len() - 32..]);
                return Ok(key);
            } else {
                anyhow::bail!("Invalid key length in PEM: expected 32 bytes, got {}", bytes.len());
            }
        }

        // Check Hex format (64 hex characters)
        if text_trimmed.len() == 64 {
            if let Ok(bytes) = hex::decode(text_trimmed) {
                if bytes.len() == 32 {
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&bytes);
                    return Ok(key);
                }
            }
        }

        // Check raw Base64 format
        use base64::Engine;
        if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(text_trimmed) {
            if bytes.len() == 32 {
                let mut key = [0u8; 32];
                key.copy_from_slice(&bytes);
                return Ok(key);
            }
        }

        anyhow::bail!("Unrecognized key format: expected standard PEM, 64-char Hex, 44-char Base64, or 32 raw bytes")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pem_encode_decode_roundtrip() -> anyhow::Result<()> {
        let (priv_key, pub_key) = PluginCrypto::generate_keypair();
        let priv_pem = PluginCrypto::encode_private_key_pem(&priv_key);
        let pub_pem = PluginCrypto::encode_public_key_pem(&pub_key);

        assert!(priv_pem.contains("-----BEGIN PRIVATE KEY-----"));
        assert!(pub_pem.contains("-----BEGIN PUBLIC KEY-----"));

        let decoded_priv = PluginCrypto::decode_key_bytes(priv_pem.as_bytes())?;
        let decoded_pub = PluginCrypto::decode_key_bytes(pub_pem.as_bytes())?;

        assert_eq!(priv_key, decoded_priv);
        assert_eq!(pub_key, decoded_pub);
        Ok(())
    }

    #[test]
    fn test_hex_and_raw_decode() -> anyhow::Result<()> {
        let (priv_key, _) = PluginCrypto::generate_keypair();
        let hex_str = hex::encode(priv_key);
        let decoded_hex = PluginCrypto::decode_key_bytes(hex_str.as_bytes())?;
        assert_eq!(priv_key, decoded_hex);

        let decoded_raw = PluginCrypto::decode_key_bytes(&priv_key)?;
        assert_eq!(priv_key, decoded_raw);
        Ok(())
    }

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
