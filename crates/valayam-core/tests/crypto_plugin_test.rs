use valayam_crypto::PluginCrypto;

#[test]
fn test_plugin_crypto_sign_and_verify() {
    let message = b"hello valayam plugin";

    // 1. Generate keypair
    let (priv_key, pub_key) = PluginCrypto::generate_keypair();

    // 2. Sign message
    let signature = PluginCrypto::sign(&priv_key, message).expect("Failed to sign");

    // 3. Verify signature
    let is_valid = PluginCrypto::verify(&pub_key, message, &signature).expect("Failed to verify");
    assert!(is_valid, "Signature should be valid");

    // 4. Verify tampering
    let mut tampered_message = message.to_vec();
    tampered_message[0] = b'H';
    let is_valid_tampered =
        PluginCrypto::verify(&pub_key, &tampered_message, &signature).expect("Failed to verify");
    assert!(
        !is_valid_tampered,
        "Signature should be invalid for tampered message"
    );

    // 5. Verify bad key
    let (_, other_pub_key) = PluginCrypto::generate_keypair();
    let is_valid_other_key =
        PluginCrypto::verify(&other_pub_key, message, &signature).expect("Failed to verify");
    assert!(
        !is_valid_other_key,
        "Signature should be invalid with different public key"
    );
}
