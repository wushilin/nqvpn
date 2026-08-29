//! The coordinator's single source of truth on disk: one SQLite file.
//!
//! Two kinds of rows, both JSON: a network's *configuration* (what the
//! operator decided in the UI — address space, settings, members and
//! their secrets) and its *registry* (what the coordinator learned —
//! node ids, addresses handed out, login generations, the generation
//! high-water mark). Everything that must survive a restart is here;
//! everything else is recomputed from heartbeats.
//!
//! Writes are transactional and `synchronous=FULL`: a token the operator
//! has been shown, or a node id a member has been given, is on disk
//! before it is visible.

use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use std::sync::Mutex;

use crate::config::NetworkConfig;
use crate::registry::Registry;

pub struct Db {
    conn: Mutex<Connection>,
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS networks (
    network_id TEXT PRIMARY KEY,
    config     TEXT NOT NULL,
    updated_unix INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS registries (
    network_id TEXT PRIMARY KEY REFERENCES networks(network_id) ON DELETE CASCADE,
    data       TEXT NOT NULL,
    updated_unix INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
";

impl Db {
    pub fn open(path: &Path) -> Result<Db> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        let conn = Connection::open(path).with_context(|| format!("opening {}", path.display()))?;
        Self::init(conn)
    }

    /// For tests: everything in memory, same code paths.
    pub fn open_memory() -> Result<Db> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Db> {
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = FULL;
             PRAGMA foreign_keys = ON;",
        )?;
        conn.execute_batch(SCHEMA)?;
        conn.execute(
            "INSERT OR IGNORE INTO meta(key, value) VALUES ('schema_version', '1')",
            [],
        )?;
        Ok(Db { conn: Mutex::new(conn) })
    }

    /// Every network with its registry (a fresh one if none was saved).
    pub fn load_all(&self) -> Result<Vec<(NetworkConfig, Registry)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT n.network_id, n.config, r.data FROM networks n
             LEFT JOIN registries r ON r.network_id = n.network_id
             ORDER BY n.network_id",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, Option<String>>(2)?))
        })?;
        let mut out = Vec::new();
        for r in rows {
            let (id, cfg_json, reg_json) = r?;
            let cfg: NetworkConfig =
                serde_json::from_str(&cfg_json).with_context(|| format!("network {id}: stored config"))?;
            let reg: Registry = match reg_json {
                Some(j) => serde_json::from_str(&j).with_context(|| format!("network {id}: stored registry"))?,
                None => Registry::new(),
            };
            out.push((cfg, reg));
        }
        Ok(out)
    }

    pub fn save_network(&self, cfg: &NetworkConfig) -> Result<()> {
        let json = serde_json::to_string(cfg)?;
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO networks(network_id, config, updated_unix) VALUES (?1, ?2, ?3)
             ON CONFLICT(network_id) DO UPDATE SET config = excluded.config, updated_unix = excluded.updated_unix",
            params![cfg.network_id, json, crate::state::now_unix() as i64],
        )?;
        Ok(())
    }

    pub fn save_registry(&self, network_id: &str, reg: &Registry) -> Result<()> {
        let json = serde_json::to_string(reg)?;
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO registries(network_id, data, updated_unix) VALUES (?1, ?2, ?3)
             ON CONFLICT(network_id) DO UPDATE SET data = excluded.data, updated_unix = excluded.updated_unix",
            params![network_id, json, crate::state::now_unix() as i64],
        )?;
        Ok(())
    }

    /// Config and registry in one transaction (network creation).
    pub fn save_network_and_registry(&self, cfg: &NetworkConfig, reg: &Registry) -> Result<()> {
        let cfg_json = serde_json::to_string(cfg)?;
        let reg_json = serde_json::to_string(reg)?;
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        let now = crate::state::now_unix() as i64;
        tx.execute(
            "INSERT INTO networks(network_id, config, updated_unix) VALUES (?1, ?2, ?3)
             ON CONFLICT(network_id) DO UPDATE SET config = excluded.config, updated_unix = excluded.updated_unix",
            params![cfg.network_id, cfg_json, now],
        )?;
        tx.execute(
            "INSERT INTO registries(network_id, data, updated_unix) VALUES (?1, ?2, ?3)
             ON CONFLICT(network_id) DO UPDATE SET data = excluded.data, updated_unix = excluded.updated_unix",
            params![cfg.network_id, reg_json, now],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn delete_network(&self, network_id: &str) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let n = conn.execute("DELETE FROM networks WHERE network_id = ?1", params![network_id])?;
        Ok(n > 0)
    }

    pub fn load_registry(&self, network_id: &str) -> Result<Option<Registry>> {
        let conn = self.conn.lock().unwrap();
        let json: Option<String> = conn
            .query_row("SELECT data FROM registries WHERE network_id = ?1", params![network_id], |r| r.get(0))
            .optional()?;
        Ok(match json {
            Some(j) => Some(serde_json::from_str(&j)?),
            None => None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(id: &str) -> NetworkConfig {
        serde_json::from_str(&format!(
            r#"{{"network_id":"{id}","cidrs":["10.99.0.0/16"],"pools":{{}},"settings":{{}},"relays":{{}},"clients":{{}}}}"#
        ))
        .unwrap()
    }

    #[test]
    fn networks_and_registries_round_trip() {
        let db = Db::open_memory().unwrap();
        assert!(db.load_all().unwrap().is_empty());
        let reg = Registry::new();
        db.save_network_and_registry(&cfg("a"), &reg).unwrap();
        db.save_network(&cfg("b")).unwrap();
        let all = db.load_all().unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].0.network_id, "a");
        assert_eq!(all[0].1.network_uuid, reg.network_uuid, "saved registry comes back");
        assert_ne!(all[1].1.network_uuid, reg.network_uuid, "a network without one gets a fresh registry");
        assert!(db.delete_network("a").unwrap());
        assert!(!db.delete_network("a").unwrap());
        assert!(db.load_registry("a").unwrap().is_none(), "cascades");
        assert_eq!(db.load_all().unwrap().len(), 1);
    }

    #[test]
    fn a_file_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nqvpn.db");
        {
            let db = Db::open(&path).unwrap();
            db.save_network_and_registry(&cfg("a"), &Registry::new()).unwrap();
        }
        let db = Db::open(&path).unwrap();
        assert_eq!(db.load_all().unwrap().len(), 1);
    }
}
