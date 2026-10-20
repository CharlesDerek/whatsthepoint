use argon2::{
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
    password_hash::{SaltString, rand_core::OsRng},
};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    net::IpAddr,
    time::{Duration, Instant},
};

pub fn token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

pub fn digest(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

pub fn hash_password(password: &str) -> anyhow::Result<String> {
    if password.len() < 12 || password.len() > 1024 {
        anyhow::bail!("password must be between 12 and 1024 bytes");
    }
    Argon2::default()
        .hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng))
        .map(|hash| hash.to_string())
        .map_err(|e| anyhow::anyhow!("{e}"))
}

pub fn verify(password: &str, encoded: &str) -> bool {
    PasswordHash::new(encoded).is_ok_and(|hash| {
        Argon2::default()
            .verify_password(password.as_bytes(), &hash)
            .is_ok()
    })
}

#[derive(Default)]
pub struct LoginLimiter {
    attempts: HashMap<IpAddr, (Instant, u32)>,
}

impl LoginLimiter {
    pub fn permit(&mut self, ip: IpAddr) -> bool {
        let now = Instant::now();
        self.attempts
            .retain(|_, (at, _)| now.duration_since(*at) < Duration::from_secs(300));
        if self.attempts.len() >= 4096 && !self.attempts.contains_key(&ip) {
            return false;
        }
        let entry = self.attempts.entry(ip).or_insert((now, 0));
        entry.1 += 1;
        entry.1 <= 10
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn salted_passwords_and_tokens() {
        let hash = hash_password("correct horse battery staple").unwrap();
        assert!(verify("correct horse battery staple", &hash));
        assert!(!verify("wrong", &hash));
        assert!(hash_password("short").is_err());
        assert_ne!(token(), token());
    }
    #[test]
    fn throttles_login() {
        let mut limiter = LoginLimiter::default();
        let ip = "127.0.0.1".parse().unwrap();
        for _ in 0..10 {
            assert!(limiter.permit(ip));
        }
        assert!(!limiter.permit(ip));
    }
}
