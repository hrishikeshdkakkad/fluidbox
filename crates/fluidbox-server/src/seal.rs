//! Credential sealing for integration connections.
//!
//! Connections hold durable external-service credentials (e.g. a GitHub
//! token). At rest they are AEAD-sealed with a server-side key; the plaintext
//! exists only (a) at the API boundary when the user pastes it in, and (b)
//! for the duration of a control-plane-side operation (workspace fetch,
//! provider API call). It never enters a RunSpec, sandbox, ledger, artifact,
//! or API response.

use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};

const NONCE_LEN: usize = 24;

#[derive(Clone)]
pub struct Sealer {
    key: Key,
}

impl Sealer {
    /// Accepts a 32-byte key as 64 hex chars or standard base64.
    pub fn from_key_string(s: &str) -> anyhow::Result<Self> {
        let s = s.trim();
        let bytes = match hex::decode(s) {
            Ok(b) => b,
            Err(_) => {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD
                    .decode(s)
                    .map_err(|_| anyhow::anyhow!("FLUIDBOX_CREDENTIAL_KEY must be hex or base64"))?
            }
        };
        let key: [u8; 32] = bytes.try_into().map_err(|b: Vec<u8>| {
            anyhow::anyhow!(
                "FLUIDBOX_CREDENTIAL_KEY must decode to 32 bytes (got {})",
                b.len()
            )
        })?;
        Ok(Self {
            key: Key::from(key),
        })
    }

    /// nonce || ciphertext. A fresh random nonce per seal — XChaCha's 24-byte
    /// nonce makes random generation collision-safe without counter state.
    pub fn seal(&self, plaintext: &str) -> Vec<u8> {
        let cipher = XChaCha20Poly1305::new(&self.key);
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ct = cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .expect("XChaCha20Poly1305 encrypt is infallible for in-memory data");
        let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        out
    }

    /// Error messages stay generic on purpose — never echo key or payload.
    pub fn open(&self, sealed: &[u8]) -> anyhow::Result<String> {
        if sealed.len() <= NONCE_LEN {
            anyhow::bail!("sealed credential is malformed");
        }
        let (nonce, ct) = sealed.split_at(NONCE_LEN);
        let nonce: [u8; NONCE_LEN] = nonce.try_into().expect("split_at guarantees length");
        let cipher = XChaCha20Poly1305::new(&self.key);
        let pt = cipher
            .decrypt(&XNonce::from(nonce), ct)
            .map_err(|_| anyhow::anyhow!("credential unseal failed (wrong key or corrupt data)"))?;
        String::from_utf8(pt).map_err(|_| anyhow::anyhow!("sealed credential is malformed"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_sealer() -> Sealer {
        Sealer::from_key_string(&"ab".repeat(32)).unwrap()
    }

    #[test]
    fn seal_open_roundtrip() {
        let s = test_sealer();
        let sealed = s.seal("ghp_notARealToken1234567890");
        assert_eq!(s.open(&sealed).unwrap(), "ghp_notARealToken1234567890");
        // Ciphertext never contains the plaintext.
        assert!(!String::from_utf8_lossy(&sealed).contains("notARealToken"));
        // Fresh nonce every seal → distinct ciphertexts for the same input.
        assert_ne!(sealed, s.seal("ghp_notARealToken1234567890"));
    }

    #[test]
    fn tampered_or_truncated_fails_closed() {
        let s = test_sealer();
        let mut sealed = s.seal("secret");
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert!(s.open(&sealed).is_err());
        assert!(s.open(&[0u8; 10]).is_err());
    }

    #[test]
    fn wrong_key_fails_closed() {
        let sealed = test_sealer().seal("secret");
        let other = Sealer::from_key_string(&"cd".repeat(32)).unwrap();
        assert!(other.open(&sealed).is_err());
    }

    #[test]
    fn key_parsing_hex_and_base64() {
        use base64::Engine;
        let raw = [7u8; 32];
        let hex_key = hex::encode(raw);
        let b64_key = base64::engine::general_purpose::STANDARD.encode(raw);
        // Same key bytes → interoperable sealers.
        let a = Sealer::from_key_string(&hex_key).unwrap();
        let b = Sealer::from_key_string(&b64_key).unwrap();
        assert_eq!(b.open(&a.seal("x")).unwrap(), "x");
        // Wrong lengths are rejected.
        assert!(Sealer::from_key_string("deadbeef").is_err());
        assert!(Sealer::from_key_string("not-a-key!").is_err());
    }
}
