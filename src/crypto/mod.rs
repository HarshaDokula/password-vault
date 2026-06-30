use argon2::{
    Argon2, Algorithm, Version, Params,
};
use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{Aead, KeyInit},
    XNonce,
};
use rand::Rng;
use sha2::{Sha256, Digest};
use zeroize::Zeroize;

/// Derive a 256-bit encryption key from a master password using Argon2id.
pub fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32], String> {
    let mut key = [0u8; 32];
    
    let params = Params::new(
        4 * 1024, // 4 MB memory (reduced for constrained hardware like Raspberry Pi)
        3,         // 3 iterations (slightly more iterations compensate for less memory)
        1,         // 1 degree of parallelism
        Some(32),  // 32 byte output
    )
    .map_err(|e| format!("Argon2 params error: {}", e))?;

    let argon2 = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        params,
    );

    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| format!("Key derivation error: {}", e))?;

    Ok(key)
}

/// Generate a random salt.
pub fn generate_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    rand::thread_rng().fill(&mut salt);
    salt
}

/// Generate a random 256-bit key.
pub fn generate_random_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    rand::thread_rng().fill(&mut key);
    key
}

/// Encrypt plaintext using XChaCha20-Poly1305.
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| format!("Cipher init error: {}", e))?;
    
    let mut nonce_bytes = [0u8; 24];
    rand::thread_rng().fill(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);
    
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| format!("Encryption error: {}", e))?;
    
    // Prepend nonce to ciphertext: [nonce (24 bytes) | ciphertext]
    let mut result = nonce_bytes.to_vec();
    result.extend_from_slice(&ciphertext);
    
    Ok(result)
}

/// Decrypt ciphertext using XChaCha20-Poly1305.
pub fn decrypt(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < 24 {
        return Err("Ciphertext too short".to_string());
    }
    
    let (nonce_bytes, ciphertext) = data.split_at(24);
    let nonce = XNonce::from_slice(nonce_bytes);
    
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| format!("Cipher init error: {}", e))?;
    
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("Decryption error: {}", e))
}

/// Decrypt a string (UTF-8) from encrypted bytes.
pub fn decrypt_string(key: &[u8; 32], data: &[u8]) -> Result<String, String> {
    let bytes = decrypt(key, data)?;
    String::from_utf8(bytes).map_err(|e| format!("UTF-8 decode error: {}", e))
}

/// Encrypt a string.
pub fn encrypt_string(key: &[u8; 32], s: &str) -> Result<Vec<u8>, String> {
    encrypt(key, s.as_bytes())
}

/// Generate validation token (random 32 bytes) and encrypt it with the derived key.
pub fn create_validation_token(key: &[u8; 32]) -> Result<Vec<u8>, String> {
    let token = generate_random_key();
    encrypt(key, &token)
}

/// Verify the validation token by attempting decryption.
pub fn verify_validation_token(key: &[u8; 32], encrypted_token: &[u8]) -> Result<(), String> {
    decrypt(key, encrypted_token)?;
    Ok(())
}

/// Compute SHA-256 hash of bytes.
pub fn sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Compute SHA-256 hash and return as hex string.
pub fn sha256_hex(data: &[u8]) -> String {
    hex_encode(&sha256(data))
}

/// Hex-encode bytes.
pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Clear sensitive data from a byte vector.
pub fn secure_clear(data: &mut Vec<u8>) {
    data.zeroize();
}

/// Configuration encryption key for encrypting the config file.
/// In v1 we use a fixed key derived from the vault path.
pub fn derive_config_key(vault_path: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"vault-config-salt-v1:");
    hasher.update(vault_path.as_bytes());
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = generate_random_key();
        let plaintext = b"hello world this is a test";
        
        let encrypted = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &encrypted).unwrap();
        
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_decrypt_string() {
        let key = generate_random_key();
        let plaintext = "Hello, 世界!";
        
        let encrypted = encrypt_string(&key, plaintext).unwrap();
        let decrypted = decrypt_string(&key, &encrypted).unwrap();
        
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_derived_key() {
        let salt = generate_salt();
        let key1 = derive_key("password123", &salt).unwrap();
        let key2 = derive_key("password123", &salt).unwrap();
        assert_eq!(key1, key2);
        
        let key3 = derive_key("different", &salt).unwrap();
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_validation_token() {
        let key = generate_random_key();
        let token = create_validation_token(&key).unwrap();
        assert!(verify_validation_token(&key, &token).is_ok());
        
        let wrong_key = generate_random_key();
        assert!(verify_validation_token(&wrong_key, &token).is_err());
    }

    #[test]
    fn test_sha256() {
        let hash1 = sha256_hex(b"hello");
        let hash2 = sha256_hex(b"hello");
        assert_eq!(hash1, hash2);
        
        let hash3 = sha256_hex(b"world");
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_encrypt_different_nonces() {
        let key = generate_random_key();
        let plaintext = b"test";
        
        let enc1 = encrypt(&key, plaintext).unwrap();
        let enc2 = encrypt(&key, plaintext).unwrap();
        
        // Same plaintext should produce different ciphertext due to random nonce
        assert_ne!(enc1, enc2);
    }
}
