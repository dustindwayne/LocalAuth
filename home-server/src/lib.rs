use anyhow::{bail, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey;
use rand::RngCore;
use redb::{Database, ReadableTable, ReadableTableMetadata, TableDefinition};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const DEVICES: TableDefinition<&str, &[u8]> = TableDefinition::new("devices");
const BACKUPS: TableDefinition<&str, &[u8]> = TableDefinition::new("backups");
pub const MAX_BLOB: usize = 4 * 1024 * 1024;
pub const KEEP: usize = 10;
const MAX_PENDING_PER_DEVICE: usize = 4;
const MAX_REPLAYS_PER_DEVICE: usize = 128;
const MAX_HISTORICAL_DEVICES: u64 = 256;
#[derive(Serialize, Deserialize, Clone)]
pub struct Device {
    pub id: String,
    pub label: String,
    pub public_key: String,
    pub paired: u64,
    #[serde(default)]
    pub revoked: bool,
}
#[derive(Serialize)]
pub struct Snapshot {
    pub id: String,
    pub bytes: usize,
}
pub struct PairTicket {
    pub expires: Instant,
}
pub struct Challenge {
    pub device: String,
    pub expires: Instant,
}
pub struct Store {
    pub db: Database,
    pub tickets: Mutex<HashMap<String, PairTicket>>,
    pub challenges: Mutex<HashMap<String, Challenge>>,
    bootstrap_replays: Mutex<HashMap<String, Instant>>,
}
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
pub fn random() -> String {
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    B64.encode(b)
}
pub fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
pub fn canonical(device: &str, nonce: &str, method: &str, path: &str, body: &[u8]) -> String {
    format!(
        "LocalAuth request v2\n{device}\n{nonce}\n{method}\n{path}\n{}",
        hash(body)
    )
}
pub fn pair_canonical(pin: &str, ticket: &str, public_key: &str, label: &str) -> String {
    format!(
        "LocalAuth pair v2\n{pin}\n{ticket}\n{public_key}\n{}",
        hash(label.as_bytes())
    )
}
pub fn challenge_canonical(pin: &str, device: &str, nonce: &str, timestamp: u64) -> String {
    format!("LocalAuth challenge v2\n{pin}\n{device}\n{nonce}\n{timestamp}")
}
fn verify_proof(public_key: &str, proof: &str, message: &str) -> Result<()> {
    if public_key.len() > 344 || proof.len() > 128 {
        bail!("Oversized proof")
    }
    let key = VerifyingKey::from_public_key_der(&B64.decode(public_key)?)?;
    let signature = Signature::from_der(&B64.decode(proof)?)?;
    key.verify(message.as_bytes(), &signature)?;
    Ok(())
}
impl Store {
    pub fn open(path: &std::path::Path) -> Result<Arc<Self>> {
        let db = Database::create(path)?;
        let w = db.begin_write()?;
        {
            w.open_table(DEVICES)?;
            w.open_table(BACKUPS)?;
        }
        w.commit()?;
        Ok(Arc::new(Self {
            db,
            tickets: Mutex::new(HashMap::new()),
            challenges: Mutex::new(HashMap::new()),
            bootstrap_replays: Mutex::new(HashMap::new()),
        }))
    }
    pub fn ticket(&self) -> Result<String> {
        let mut tickets = self.tickets.lock().unwrap();
        tickets.retain(|_, v| v.expires > Instant::now());
        if tickets.len() >= 16 {
            bail!("Too many pending pairings")
        }
        let t = random();
        tickets.insert(
            hash(t.as_bytes()),
            PairTicket {
                expires: Instant::now() + Duration::from_secs(300),
            },
        );
        Ok(t)
    }
    pub fn pair_signed(
        &self,
        pin: &str,
        ticket: &str,
        public_key: &str,
        label: &str,
        proof: &str,
    ) -> Result<Device> {
        if ticket.len() != 43 || label.is_empty() || label.len() > 80 {
            bail!("Invalid pairing")
        }
        verify_proof(
            public_key,
            proof,
            &pair_canonical(pin, ticket, public_key, label),
        )?;
        self.pair(ticket, public_key, label)
    }
    fn pair(&self, ticket: &str, public_key: &str, label: &str) -> Result<Device> {
        if label.is_empty() || label.len() > 80 {
            bail!("Invalid label")
        }
        let key = B64.decode(public_key)?;
        if key.len() > 256 {
            bail!("Invalid key")
        };
        VerifyingKey::from_public_key_der(&key)?;
        let mut tickets = self.tickets.lock().unwrap();
        let ticket_hash = hash(ticket.as_bytes());
        if tickets
            .get(&ticket_hash)
            .is_none_or(|t| t.expires <= Instant::now())
        {
            bail!("Pairing expired")
        }
        let mut d = Device {
            id: random(),
            label: label.to_owned(),
            public_key: public_key.to_owned(),
            paired: now(),
            revoked: false,
        };
        let w = self.db.begin_write()?;
        {
            let mut t = w.open_table(DEVICES)?;
            let mut existing = None;
            let mut active = 0;
            for row in t.iter()? {
                let (_, value) = row?;
                let device: Device = serde_json::from_slice(value.value())?;
                if !device.revoked {
                    active += 1;
                }
                if !device.revoked && device.public_key == public_key {
                    existing = Some(device);
                }
            }
            if let Some(device) = existing {
                d = device;
            } else {
                if active >= 16 || t.len()? >= MAX_HISTORICAL_DEVICES {
                    bail!("Device limit reached")
                };
                let bytes = serde_json::to_vec(&d)?;
                t.insert(d.id.as_str(), bytes.as_slice())?;
            }
        }
        w.commit()?;
        tickets.remove(&ticket_hash);
        Ok(d)
    }
    pub fn devices(&self) -> Result<Vec<Device>> {
        let r = self.db.begin_read()?;
        let t = r.open_table(DEVICES)?;
        t.iter()?
            .map(|item| {
                let (_, v) = item?;
                Ok(serde_json::from_slice(v.value())?)
            })
            .collect()
    }
    pub fn device(&self, id: &str) -> Result<Device> {
        let r = self.db.begin_read()?;
        let t = r.open_table(DEVICES)?;
        let value = t
            .get(id)?
            .ok_or_else(|| anyhow::anyhow!("Unknown device"))?;
        let d: Device = serde_json::from_slice(value.value())?;
        if d.revoked {
            bail!("Revoked device")
        };
        Ok(d)
    }
    pub fn revoke(&self, id: &str) -> Result<()> {
        let mut device = self.device(id)?;
        device.revoked = true;
        let w = self.db.begin_write()?;
        {
            let bytes = serde_json::to_vec(&device)?;
            w.open_table(DEVICES)?.insert(id, bytes.as_slice())?;
        }
        w.commit()?;
        self.challenges
            .lock()
            .unwrap()
            .retain(|_, v| v.device != id);
        Ok(())
    }
    pub fn challenge_signed(
        &self,
        pin: &str,
        id: &str,
        nonce: &str,
        timestamp: u64,
        proof: &str,
    ) -> Result<String> {
        if nonce.len() != 43 || B64.decode(nonce)?.len() != 32 || now().abs_diff(timestamp) > 60_000
        {
            bail!("Invalid bootstrap freshness")
        }
        let device = self.device(id)?;
        verify_proof(
            &device.public_key,
            proof,
            &challenge_canonical(pin, id, nonce, timestamp),
        )?;
        let replay_key = format!("{id}:{nonce}");
        let mut replays = self.bootstrap_replays.lock().unwrap();
        replays.retain(|_, expiry| *expiry > Instant::now());
        if replays.contains_key(&replay_key) {
            bail!("Replayed bootstrap")
        }
        let prefix = format!("{id}:");
        if replays
            .keys()
            .filter(|key| key.starts_with(&prefix))
            .count()
            >= MAX_REPLAYS_PER_DEVICE
        {
            bail!("Device bootstrap rate exceeded")
        }
        // Retain through the entire timestamp acceptance window, including future timestamps.
        let challenge = self.challenge(id)?;
        replays.insert(replay_key, Instant::now() + Duration::from_secs(120));
        Ok(challenge)
    }
    fn challenge(&self, id: &str) -> Result<String> {
        self.device(id)?;
        let mut map = self.challenges.lock().unwrap();
        map.retain(|_, v| v.expires > Instant::now());
        if map.values().filter(|ch| ch.device == id).count() >= MAX_PENDING_PER_DEVICE {
            bail!("Challenge limit reached")
        }
        let nonce = random();
        map.insert(
            nonce.clone(),
            Challenge {
                device: id.to_owned(),
                expires: Instant::now() + Duration::from_secs(60),
            },
        );
        Ok(nonce)
    }
    pub fn verify(
        &self,
        id: &str,
        nonce: &str,
        signature: &str,
        method: &str,
        path: &str,
        body: &[u8],
    ) -> Result<()> {
        let d = self.device(id)?;
        let mut map = self.challenges.lock().unwrap();
        let ch = map
            .get(nonce)
            .ok_or_else(|| anyhow::anyhow!("Missing challenge"))?;
        if ch.device != id || ch.expires <= Instant::now() {
            bail!("Expired challenge")
        }
        let key = VerifyingKey::from_public_key_der(&B64.decode(d.public_key)?)?;
        let sig = Signature::from_der(&B64.decode(signature)?)?;
        key.verify(canonical(id, nonce, method, path, body).as_bytes(), &sig)?;
        map.remove(nonce);
        Ok(())
    }
    pub fn save(&self, id: &str, blob: &[u8]) -> Result<String> {
        self.device(id)?;
        let legacy = blob.len() >= 33 && &blob[..4] == b"LAB1";
        let public_key = blob.len() >= 418 && &blob[..4] == b"LAB2" && blob[4..6] == [1, 128];
        if blob.len() > MAX_BLOB || !(legacy || public_key) {
            bail!("Invalid encrypted backup")
        }
        let version;
        let w = self.db.begin_write()?;
        {
            let mut t = w.open_table(BACKUPS)?;
            let prefix = format!("{id}:");
            let mut keys = Vec::new();
            for row in t.iter()? {
                let (k, _) = row?;
                if k.value().starts_with(&prefix) {
                    keys.push(k.value().to_owned())
                }
            }
            let previous = keys
                .last()
                .map(|key| key.split(':').nth(1).unwrap().parse::<u64>())
                .transpose()?
                .unwrap_or(0);
            version = format!(
                "{id}:{:020}:{}",
                now().max(previous.saturating_add(1)),
                random()
            );
            t.insert(version.as_str(), blob)?;
            keys.push(version.clone());
            for old in keys.iter().take(keys.len().saturating_sub(KEEP)) {
                t.remove(old.as_str())?;
            }
        }
        w.commit()?;
        Ok(version)
    }
    pub fn snapshots(&self, id: &str) -> Result<Vec<Snapshot>> {
        let r = self.db.begin_read()?;
        let t = r.open_table(BACKUPS)?;
        let prefix = format!("{id}:");
        let mut out = Vec::new();
        for i in t.iter()? {
            let (k, v) = i?;
            if k.value().starts_with(&prefix) {
                out.push(Snapshot {
                    id: k.value().to_owned(),
                    bytes: v.value().len(),
                })
            }
        }
        out.reverse();
        Ok(out)
    }
    pub fn latest(&self, id: &str) -> Result<Vec<u8>> {
        let snap = self
            .snapshots(id)?
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("No backup"))?;
        let r = self.db.begin_read()?;
        let t = r.open_table(BACKUPS)?;
        let value = t
            .get(snap.id.as_str())?
            .ok_or_else(|| anyhow::anyhow!("No backup"))?;
        Ok(value.value().to_vec())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Signer, SigningKey};
    use p256::pkcs8::EncodePublicKey;
    fn setup() -> (tempfile::TempDir, Arc<Store>, Device, SigningKey) {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(&temp.path().join("db")).unwrap();
        let key = SigningKey::random(&mut rand::rngs::OsRng);
        let public = B64.encode(key.verifying_key().to_public_key_der().unwrap().as_bytes());
        let ticket = store.ticket().unwrap();
        let d = store.pair(&ticket, &public, "test").unwrap();
        assert!(store.pair(&ticket, &public, "clone").is_err());
        (temp, store, d, key)
    }
    #[test]
    fn challenge_binds_body_and_rejects_replay_and_clone() {
        let (_tmp, s, d, key) = setup();
        let n = s.challenge(&d.id).unwrap();
        let msg = canonical(&d.id, &n, "POST", "/v1/backup", b"hello");
        let sig: Signature = key.sign(msg.as_bytes());
        let sig = B64.encode(sig.to_der());
        assert!(s
            .verify(&d.id, &n, &sig, "POST", "/v1/backup", b"changed")
            .is_err());
        let clone = SigningKey::random(&mut rand::rngs::OsRng);
        let fake: Signature = clone.sign(msg.as_bytes());
        assert!(s
            .verify(
                &d.id,
                &n,
                &B64.encode(fake.to_der()),
                "POST",
                "/v1/backup",
                b"hello"
            )
            .is_err());
        s.verify(&d.id, &n, &sig, "POST", "/v1/backup", b"hello")
            .unwrap();
        assert!(s
            .verify(&d.id, &n, &sig, "POST", "/v1/backup", b"hello")
            .is_err());
    }
    #[test]
    fn expired_and_cross_device_challenges_fail() {
        let (_tmp, s, d, key) = setup();
        let n = s.challenge(&d.id).unwrap();
        s.challenges.lock().unwrap().get_mut(&n).unwrap().expires =
            Instant::now() - Duration::from_secs(1);
        let sig: Signature = key.sign(canonical(&d.id, &n, "GET", "/v1/backup", b"").as_bytes());
        assert!(s
            .verify(
                &d.id,
                &n,
                &B64.encode(sig.to_der()),
                "GET",
                "/v1/backup",
                b""
            )
            .is_err());
    }
    #[test]
    fn revoked_device_cannot_authenticate_and_retention_is_bounded() {
        let (_tmp, s, d, _) = setup();
        for i in 0..15 {
            let mut b = b"LAB1".to_vec();
            b.extend_from_slice(&[i; 40]);
            s.save(&d.id, &b).unwrap();
        }
        assert_eq!(s.snapshots(&d.id).unwrap().len(), KEEP);
        assert_eq!(s.latest(&d.id).unwrap()[4], 14);
        s.revoke(&d.id).unwrap();
        assert!(s.challenge(&d.id).is_err());
    }
    #[test]
    fn encrypted_blobs_persist_and_cross_device_ids_do_not_leak() {
        let (tmp, s, d, _) = setup();
        let blob = [b"LAB1".as_slice(), &[1u8; 40]].concat();
        s.save(&d.id, &blob).unwrap();
        drop(s);
        let reopened = Store::open(&tmp.path().join("db")).unwrap();
        assert_eq!(reopened.latest(&d.id).unwrap(), blob);
        let t = reopened.ticket().unwrap();
        let key = SigningKey::random(&mut rand::rngs::OsRng);
        let public = B64.encode(key.verifying_key().to_public_key_der().unwrap().as_bytes());
        let other = reopened.pair(&t, &public, "other").unwrap();
        assert!(reopened.latest(&other.id).is_err());
    }
    #[test]
    fn pairing_retry_keeps_the_same_device_identity() {
        let (_tmp, s, d, key) = setup();
        let public = B64.encode(key.verifying_key().to_public_key_der().unwrap().as_bytes());
        let ticket = s.ticket().unwrap();
        assert_eq!(s.pair(&ticket, &public, "retry").unwrap().id, d.id);
        assert_eq!(s.devices().unwrap().len(), 1);
    }
    #[test]
    fn signature_binds_method_path_and_challenge_device() {
        let (_tmp, s, d, key) = setup();
        let nonce = s.challenge(&d.id).unwrap();
        let sig: Signature =
            key.sign(canonical(&d.id, &nonce, "POST", "/v1/backup", b"body").as_bytes());
        let sig = B64.encode(sig.to_der());
        assert!(s
            .verify(&d.id, &nonce, &sig, "GET", "/v1/backup", b"body")
            .is_err());
        assert!(s
            .verify(&d.id, &nonce, &sig, "POST", "/other", b"body")
            .is_err());
        let other = SigningKey::random(&mut rand::rngs::OsRng);
        let ticket = s.ticket().unwrap();
        let public = B64.encode(
            other
                .verifying_key()
                .to_public_key_der()
                .unwrap()
                .as_bytes(),
        );
        let other = s.pair(&ticket, &public, "other").unwrap();
        assert!(s
            .verify(&other.id, &nonce, &sig, "POST", "/v1/backup", b"body")
            .is_err());
    }
    fn proof(key: &SigningKey, message: String) -> String {
        let signature: Signature = key.sign(message.as_bytes());
        B64.encode(signature.to_der())
    }
    #[test]
    fn signed_pairing_requires_private_key_and_binds_offer() {
        let (_tmp, s, d, key) = setup();
        let ticket = s.ticket().unwrap();
        let pin = "test-server-pin";
        let signed = proof(&key, pair_canonical(pin, &ticket, &d.public_key, "paired"));
        assert!(s
            .pair_signed(pin, &ticket, &d.public_key, "paired", "")
            .is_err());
        assert!(s
            .pair_signed("different-pin", &ticket, &d.public_key, "paired", &signed)
            .is_err());
        assert!(s
            .pair_signed(pin, &ticket, &d.public_key, "changed", &signed)
            .is_err());
        assert_eq!(
            s.pair_signed(pin, &ticket, &d.public_key, "paired", &signed)
                .unwrap()
                .id,
            d.id
        );
        assert!(s
            .pair_signed(pin, &ticket, &d.public_key, "paired", &signed)
            .is_err());
    }
    #[test]
    fn bootstrap_requires_fresh_signed_proof_before_allocation_and_rejects_replay() {
        let (_tmp, s, d, key) = setup();
        let nonce = random();
        let timestamp = now();
        let pin = "server-pin";
        let signed = proof(&key, challenge_canonical(pin, &d.id, &nonce, timestamp));
        assert!(s
            .challenge_signed(pin, &d.id, &nonce, timestamp, "")
            .is_err());
        assert!(s
            .challenge_signed("wrong", &d.id, &nonce, timestamp, &signed)
            .is_err());
        assert!(s
            .challenge_signed(pin, &d.id, &random(), timestamp, &signed)
            .is_err());
        let expired = timestamp.saturating_sub(60_001);
        let expired_proof = proof(&key, challenge_canonical(pin, &d.id, &nonce, expired));
        assert!(s
            .challenge_signed(pin, &d.id, &nonce, expired, &expired_proof)
            .is_err());
        assert!(s.challenges.lock().unwrap().is_empty());
        assert!(s.bootstrap_replays.lock().unwrap().is_empty());
        s.challenge_signed(pin, &d.id, &nonce, timestamp, &signed)
            .unwrap();
        assert!(s
            .challenge_signed(pin, &d.id, &nonce, timestamp, &signed)
            .is_err());
        assert_eq!(s.challenges.lock().unwrap().len(), 1);
    }
    #[test]
    fn one_authenticated_device_cannot_starve_other_devices() {
        let (_tmp, s, d, key) = setup();
        let pin = "pin";
        for _ in 0..MAX_PENDING_PER_DEVICE {
            let nonce = random();
            let time = now();
            let signed = proof(&key, challenge_canonical(pin, &d.id, &nonce, time));
            s.challenge_signed(pin, &d.id, &nonce, time, &signed)
                .unwrap();
        }
        let nonce = random();
        let time = now();
        let signed = proof(&key, challenge_canonical(pin, &d.id, &nonce, time));
        assert!(s
            .challenge_signed(pin, &d.id, &nonce, time, &signed)
            .is_err());
        let other_key = SigningKey::random(&mut rand::rngs::OsRng);
        let public = B64.encode(
            other_key
                .verifying_key()
                .to_public_key_der()
                .unwrap()
                .as_bytes(),
        );
        let ticket = s.ticket().unwrap();
        let other = s.pair(&ticket, &public, "other").unwrap();
        let signed = proof(
            &other_key,
            challenge_canonical(pin, &other.id, &nonce, time),
        );
        assert!(s
            .challenge_signed(pin, &other.id, &nonce, time, &signed)
            .is_ok());
    }
    #[test]
    fn revoked_history_does_not_consume_active_pairing_capacity() {
        let (_tmp, s, d, _) = setup();
        s.revoke(&d.id).unwrap();
        for _ in 0..20 {
            let key = SigningKey::random(&mut rand::rngs::OsRng);
            let public = B64.encode(key.verifying_key().to_public_key_der().unwrap().as_bytes());
            let ticket = s.ticket().unwrap();
            let device = s.pair(&ticket, &public, "replacement").unwrap();
            s.revoke(&device.id).unwrap();
        }
        assert_eq!(s.devices().unwrap().len(), 21);
    }
    #[test]
    fn bootstrap_replay_memory_is_bounded_per_device() {
        let (_tmp, s, d, key) = setup();
        let pin = "pin";
        for _ in 0..MAX_REPLAYS_PER_DEVICE {
            let client_nonce = random();
            let timestamp = now();
            let signed = proof(
                &key,
                challenge_canonical(pin, &d.id, &client_nonce, timestamp),
            );
            let server_nonce = s
                .challenge_signed(pin, &d.id, &client_nonce, timestamp, &signed)
                .unwrap();
            let request = proof(
                &key,
                canonical(&d.id, &server_nonce, "GET", "/v1/backup", b""),
            );
            s.verify(&d.id, &server_nonce, &request, "GET", "/v1/backup", b"")
                .unwrap();
        }
        let nonce = random();
        let timestamp = now();
        let signed = proof(&key, challenge_canonical(pin, &d.id, &nonce, timestamp));
        assert!(s
            .challenge_signed(pin, &d.id, &nonce, timestamp, &signed)
            .is_err());
        assert_eq!(
            s.bootstrap_replays.lock().unwrap().len(),
            MAX_REPLAYS_PER_DEVICE
        );
        assert!(s.challenges.lock().unwrap().is_empty());
    }
    #[test]
    fn active_device_limit_remains_enforced() {
        let (_tmp, s, _, _) = setup();
        for _ in 0..15 {
            let key = SigningKey::random(&mut rand::rngs::OsRng);
            let public = B64.encode(key.verifying_key().to_public_key_der().unwrap().as_bytes());
            let ticket = s.ticket().unwrap();
            s.pair(&ticket, &public, "active").unwrap();
        }
        let key = SigningKey::random(&mut rand::rngs::OsRng);
        let public = B64.encode(key.verifying_key().to_public_key_der().unwrap().as_bytes());
        let ticket = s.ticket().unwrap();
        assert!(s.pair(&ticket, &public, "overflow").is_err());
    }
    #[test]
    fn lab2_header_and_minimum_envelope_are_validated() {
        let (_tmp, s, d, _) = setup();
        let mut blob = vec![0u8; 418];
        blob[..6].copy_from_slice(&[b'L', b'A', b'B', b'2', 1, 128]);
        assert!(s.save(&d.id, &blob).is_ok());
        blob[5] = 127;
        assert!(s.save(&d.id, &blob).is_err());
        assert!(s.save(&d.id, b"LAB2").is_err());
        assert!(s.save(&d.id, &[]).is_err());
    }
}
