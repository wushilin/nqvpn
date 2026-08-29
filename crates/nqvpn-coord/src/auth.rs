//! Admin authentication. Two ways in: a UI login (user + password,
//! argon2-hashed in `coordinator.toml`) that yields a session cookie,
//! and a static bearer token for scripts. Either satisfies the admin
//! API; the UI only ever uses the session.

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use std::collections::HashMap;
use std::sync::Mutex;

use crate::state::now_unix;

pub const COOKIE: &str = "nqvpn_session";

#[derive(Debug, Clone)]
pub struct Session {
    pub user: String,
    pub expires_unix: u64,
}

#[derive(Default)]
pub struct Sessions {
    live: Mutex<HashMap<String, Session>>,
    /// Failed logins per source address, this minute.
    failures: Mutex<HashMap<String, (u64, u32)>>,
}

/// Hash a password for `coordinator.toml`.
pub fn hash_password(password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut rand::rngs::OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| e.to_string())
}

pub fn verify_password(password: &str, phc: &str) -> bool {
    match PasswordHash::new(phc) {
        Ok(parsed) => Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok(),
        Err(_) => false,
    }
}

const MAX_FAILURES_PER_MIN: u32 = 10;

impl Sessions {
    /// Too many failed logins from this address this minute?
    pub fn throttled(&self, ip: &str) -> bool {
        let window = now_unix() / 60;
        let mut f = self.failures.lock().unwrap();
        f.retain(|_, (w, _)| *w == window);
        f.get(ip).map(|(_, n)| *n >= MAX_FAILURES_PER_MIN).unwrap_or(false)
    }

    pub fn note_failure(&self, ip: &str) {
        let window = now_unix() / 60;
        let mut f = self.failures.lock().unwrap();
        let e = f.entry(ip.to_string()).or_insert((window, 0));
        if e.0 != window {
            *e = (window, 0);
        }
        e.1 += 1;
    }

    /// A fresh session token for a user who just authenticated.
    pub fn open(&self, user: &str, ttl_secs: u64) -> (String, u64) {
        let token = crate::secrets::generate_secret();
        let expires = now_unix() + ttl_secs;
        let mut live = self.live.lock().unwrap();
        live.retain(|_, s| s.expires_unix > now_unix());
        live.insert(token.clone(), Session { user: user.to_string(), expires_unix: expires });
        (token, expires)
    }

    pub fn lookup(&self, token: &str) -> Option<Session> {
        let live = self.live.lock().unwrap();
        live.get(token).filter(|s| s.expires_unix > now_unix()).cloned()
    }

    pub fn close(&self, token: &str) {
        self.live.lock().unwrap().remove(token);
    }
}

/// The session token in a Cookie header, if any.
pub fn cookie_token(headers: &axum::http::HeaderMap) -> Option<String> {
    let raw = headers.get("cookie")?.to_str().ok()?;
    raw.split(';').map(|c| c.trim()).find_map(|c| c.strip_prefix(COOKIE).and_then(|r| r.strip_prefix('=')).map(str::to_string))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify() {
        let h = hash_password("hunter2").unwrap();
        assert!(h.starts_with("$argon2"));
        assert!(verify_password("hunter2", &h));
        assert!(!verify_password("hunter3", &h));
        assert!(!verify_password("hunter2", "not-a-hash"));
    }

    #[test]
    fn sessions_open_lookup_expire_and_close() {
        let s = Sessions::default();
        let (t, exp) = s.open("admin", 60);
        assert!(exp > now_unix());
        assert_eq!(s.lookup(&t).unwrap().user, "admin");
        assert!(s.lookup("nope").is_none());
        s.close(&t);
        assert!(s.lookup(&t).is_none());
        let (t2, _) = s.open("admin", 0);
        assert!(s.lookup(&t2).is_none(), "already expired");
    }

    #[test]
    fn failures_throttle_per_minute() {
        let s = Sessions::default();
        for _ in 0..MAX_FAILURES_PER_MIN {
            assert!(!s.throttled("1.1.1.1"));
            s.note_failure("1.1.1.1");
        }
        assert!(s.throttled("1.1.1.1"));
        assert!(!s.throttled("2.2.2.2"));
    }

    #[test]
    fn cookie_parsing() {
        let mut h = axum::http::HeaderMap::new();
        h.insert("cookie", "a=b; nqvpn_session=tok123; c=d".parse().unwrap());
        assert_eq!(cookie_token(&h).as_deref(), Some("tok123"));
        h.insert("cookie", "a=b".parse().unwrap());
        assert!(cookie_token(&h).is_none());
    }
}
