//! Backup master keyring and chunked `OMBKUP01` HKDF-SHA256 + AES-256-GCM streaming cipher
//! (ADR 0046, V1-30).
//!
//! Uses only crates already locked in `Cargo.toml` (`ring`, `subtle`, `sha2`, `rustls`,
//! `serde_json`) under `unsafe_code = "forbid"`. Master key material lives outside PostgreSQL
//! and strictly separate from `VAULT_KEYS_CONFIG` (ADR 0045).

use crate::{provider_keys::documents::unique, runs};
use ring::{
    aead, hkdf,
    rand::{SecureRandom, SystemRandom},
};
use rustls::crypto::SharedSecret;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fmt, fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
};
use subtle::ConstantTimeEq;

/// Magic header identifying an OpenMettle chunked AEAD backup stream.
pub const STREAM_MAGIC: &[u8; 8] = b"OMBKUP01";
/// Plaintext chunk size for streaming AEAD encryption (64 KiB).
pub const CHUNK_SIZE: usize = 64 * 1024;
/// Byte length of every 256-bit backup master key.
pub const KEY_BYTES: usize = 32;
/// Byte length of the per-file HKDF-SHA256 salt.
pub const SALT_BYTES: usize = 32;
/// Byte length of the per-file random nonce prefix (combined with 8-byte chunk sequence).
pub const NONCE_PREFIX_BYTES: usize = 4;
/// Maximum number of keys in one [`BackupKeyRing`].
pub const MAX_KEYS: usize = 16;
const MAX_CONFIG_BYTES: usize = 64 * 1024;
const HKDF_INFO: &[u8] = b"openmettle.backup.dek/1";
const AAD_DOMAIN: &[u8] = b"openmettle.backup.aad/1\0";
const FLAG_INTERMEDIATE: u8 = 0x00;
const FLAG_FINAL: u8 = 0x01;

/// Environment variables that may point to a separate ADR 0045 vault keyring configuration.
const VAULT_CONFIG_ENV_VARS: &[&str] = &[
    "OPENMETTLE_API_VAULT_KEYS_CONFIG",
    "OPENMETTLE_WORKER_VAULT_KEYS_CONFIG",
    "OPENMETTLE_ADMIN_VAULT_KEYS_CONFIG",
    "VAULT_KEYS_CONFIG",
];

#[derive(Debug)]
pub enum CryptoError {
    Configuration(&'static str),
    Random,
    UnknownKey,
    Crypto(&'static str),
    Io(io::Error),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration(msg) => f.write_str(msg),
            Self::Random => f.write_str("backup randomness unavailable"),
            Self::UnknownKey => {
                f.write_str("backup encryption key identifier not found in keyring")
            }
            Self::Crypto(msg) => f.write_str(msg),
            Self::Io(_) => f.write_str("backup stream I/O error"),
        }
    }
}

impl std::error::Error for CryptoError {}

impl From<io::Error> for CryptoError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

fn valid_key_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyRingDocument {
    version: u32,
    active_key_id: String,
    keys: Vec<KeyEntryDocument>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyEntryDocument {
    id: String,
    file: String,
}

/// Filesystem identities associated with a loaded [`BackupKeyRing`], used to guarantee
/// destination roots and `--config-file` bundles never overlap backup key material.
#[derive(Clone, Debug, Default)]
pub struct KeyRingPaths {
    pub config_path: Option<PathBuf>,
    pub key_files: Vec<PathBuf>,
    pub protected_inodes: BTreeSet<(u64, u64)>,
}

/// Versioned backup master keyring stored separately from PostgreSQL and `VAULT_KEYS_CONFIG`.
pub struct BackupKeyRing {
    active_key_id: String,
    keys: Vec<(String, SharedSecret)>,
    paths: KeyRingPaths,
}

impl fmt::Debug for BackupKeyRing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ids: Vec<&str> = self.keys.iter().map(|(id, _)| id.as_str()).collect();
        f.debug_struct("BackupKeyRing")
            .field("active_key_id", &self.active_key_id)
            .field("key_ids", &ids)
            .finish()
    }
}

impl BackupKeyRing {
    /// Construct a validated in-memory keyring (primarily for tests).
    pub fn new(
        active_key_id: String,
        keys: Vec<(String, [u8; KEY_BYTES])>,
    ) -> Result<Self, CryptoError> {
        let wrapped = keys
            .into_iter()
            .map(|(id, bytes)| (id, SharedSecret::from(bytes.as_slice())))
            .collect();
        Self::from_shared(active_key_id, wrapped, KeyRingPaths::default())
    }

    fn from_shared(
        active_key_id: String,
        keys: Vec<(String, SharedSecret)>,
        paths: KeyRingPaths,
    ) -> Result<Self, CryptoError> {
        if keys.is_empty() || keys.len() > MAX_KEYS || !valid_key_id(&active_key_id) {
            return Err(CryptoError::Configuration("invalid backup keyring"));
        }
        let zeros = [0u8; KEY_BYTES];
        let mut seen_ids = BTreeSet::new();
        for (idx, (id, secret)) in keys.iter().enumerate() {
            if !valid_key_id(id) || !seen_ids.insert(id.as_str()) {
                return Err(CryptoError::Configuration("invalid backup key identifier"));
            }
            let bytes = secret.secret_bytes();
            if bytes.len() != KEY_BYTES || bool::from(bytes.ct_eq(&zeros)) {
                return Err(CryptoError::Configuration("invalid backup key material"));
            }
            for (_, other) in &keys[idx + 1..] {
                if bool::from(bytes.ct_eq(other.secret_bytes())) {
                    return Err(CryptoError::Configuration("duplicate backup key material"));
                }
            }
        }
        if !seen_ids.contains(active_key_id.as_str()) {
            return Err(CryptoError::Configuration("active backup key missing"));
        }
        Ok(Self {
            active_key_id,
            keys,
            paths,
        })
    }

    /// Load a version-1 backup keyring configuration file, enforcing owner-only `0400`/`0600`
    /// permissions on both the config file and every 32-byte key file, and refusing overlap
    /// with any configured ADR 0045 `VAULT_KEYS_CONFIG` file or key material.
    pub fn load_from_config(path: &Path) -> Result<Self, CryptoError> {
        let (doc_bytes, config_id) = read_owner_only_file(path, MAX_CONFIG_BYTES)?;
        let value = unique(&doc_bytes)
            .map_err(|_| CryptoError::Configuration("invalid backup keyring document"))?;
        if !value.is_object() {
            return Err(CryptoError::Configuration(
                "invalid backup keyring document",
            ));
        }
        let doc: KeyRingDocument = serde_json::from_value(value)
            .map_err(|_| CryptoError::Configuration("invalid backup keyring document"))?;
        if doc.version != 1 || doc.keys.is_empty() || doc.keys.len() > MAX_KEYS {
            return Err(CryptoError::Configuration(
                "invalid backup keyring document",
            ));
        }

        let mut paths = KeyRingPaths {
            config_path: Some(path.to_path_buf()),
            key_files: Vec::with_capacity(doc.keys.len()),
            protected_inodes: BTreeSet::new(),
        };
        if let Some(id) = config_id {
            paths.protected_inodes.insert(id);
        }

        let mut loaded = Vec::with_capacity(doc.keys.len());
        for entry in doc.keys {
            if !valid_key_id(&entry.id) {
                return Err(CryptoError::Configuration("invalid backup key identifier"));
            }
            let key_path = PathBuf::from(&entry.file);
            let (raw, key_id_ino) = read_owner_only_file(&key_path, KEY_BYTES)?;
            let secret = SharedSecret::from(raw);
            if secret.secret_bytes().len() != KEY_BYTES {
                return Err(CryptoError::Configuration("invalid backup key file"));
            }
            if let Some(id) = key_id_ino {
                paths.protected_inodes.insert(id);
            }
            paths.key_files.push(key_path);
            loaded.push((entry.id, secret));
        }

        let ring = Self::from_shared(doc.active_key_id, loaded, paths)?;
        ring.verify_distinct_from_vault_env()?;
        Ok(ring)
    }

    fn verify_distinct_from_vault_env(&self) -> Result<(), CryptoError> {
        for var in VAULT_CONFIG_ENV_VARS {
            let Ok(raw) = std::env::var(var) else {
                continue;
            };
            if raw.is_empty() {
                continue;
            }
            self.verify_distinct_from_vault_config(Path::new(&raw))?;
        }
        Ok(())
    }

    /// Verify that neither the keyring config nor any key file or key bytes match an ADR 0045
    /// vault keyring configuration.
    pub fn verify_distinct_from_vault_config(
        &self,
        vault_config: &Path,
    ) -> Result<(), CryptoError> {
        if let Some(vault_ino) = file_dev_ino(vault_config)
            && self.paths.protected_inodes.contains(&vault_ino)
        {
            return Err(CryptoError::Configuration(
                "backup keyring must be distinct from VAULT_KEYS_CONFIG",
            ));
        }
        // If the vault config is readable on this host, also verify none of its key files or raw
        // 32-byte key values match the backup keyring.
        if let Ok(vault_bytes) = fs::read(vault_config)
            && vault_bytes.len() <= MAX_CONFIG_BYTES
            && let Ok(doc) = serde_json::from_slice::<KeyRingDocument>(&vault_bytes)
        {
            for entry in &doc.keys {
                let key_path = Path::new(&entry.file);
                if let Some(ino) = file_dev_ino(key_path)
                    && self.paths.protected_inodes.contains(&ino)
                {
                    return Err(CryptoError::Configuration(
                        "backup key file must be distinct from vault key files",
                    ));
                }
                if let Ok(raw) = fs::read(key_path)
                    && raw.len() == KEY_BYTES
                {
                    let vault_secret = SharedSecret::from(raw);
                    for (_, backup_secret) in &self.keys {
                        if bool::from(
                            backup_secret
                                .secret_bytes()
                                .ct_eq(vault_secret.secret_bytes()),
                        ) {
                            return Err(CryptoError::Configuration(
                                "backup key material must be distinct from vault keys",
                            ));
                        }
                    }
                }
            }
        }
        Ok(())
    }

    pub fn active_key_id(&self) -> &str {
        &self.active_key_id
    }

    pub fn key_ids(&self) -> Vec<&str> {
        self.keys.iter().map(|(id, _)| id.as_str()).collect()
    }

    pub fn paths(&self) -> &KeyRingPaths {
        &self.paths
    }

    fn key_bytes(&self, key_id: &str) -> Result<&[u8], CryptoError> {
        self.keys
            .iter()
            .find(|(id, _)| id == key_id)
            .map(|(_, secret)| secret.secret_bytes())
            .ok_or(CryptoError::UnknownKey)
    }

    /// Encrypt one stream from `reader` directly into `writer` using `OMBKUP01` chunked
    /// HKDF-SHA256 + AES-256-GCM under the ring's `active_key_id`.
    pub fn encrypt_stream(
        &self,
        backup_run_id: &str,
        artifact_role: &str,
        reader: &mut dyn Read,
        writer: &mut dyn Write,
    ) -> Result<EncryptedStats, CryptoError> {
        let mut enc = StreamEncryptor::start(self, backup_run_id, artifact_role, writer)?;
        let mut buf = vec![0u8; CHUNK_SIZE];
        loop {
            let n = read_full_chunk(reader, &mut buf)?;
            if n == 0 {
                break;
            }
            enc.write_all(&buf[..n])?;
        }
        enc.finish()
    }

    /// Decrypt and authenticate one `OMBKUP01` stream from `reader` into `writer`, returning the
    /// header `key_id` plus plaintext and ciphertext sizes and SHA-256 digests.
    pub fn decrypt_stream(
        &self,
        backup_run_id: &str,
        artifact_role: &str,
        expected_key_id: Option<&str>,
        reader: &mut dyn Read,
        writer: &mut dyn Write,
    ) -> Result<DecryptedStats, CryptoError> {
        let mut ct_hash = Sha256::new();
        let mut pt_hash = Sha256::new();
        let mut ct_bytes: u64 = 0;
        let mut pt_bytes: u64 = 0;

        let mut magic = [0u8; 8];
        read_exact_counting(reader, &mut magic, &mut ct_hash, &mut ct_bytes)?;
        if &magic != STREAM_MAGIC {
            return Err(CryptoError::Crypto("invalid backup stream magic"));
        }

        let mut key_id_len_buf = [0u8; 2];
        read_exact_counting(reader, &mut key_id_len_buf, &mut ct_hash, &mut ct_bytes)?;
        let key_id_len = u16::from_be_bytes(key_id_len_buf) as usize;
        if !(1..=64).contains(&key_id_len) {
            return Err(CryptoError::Crypto("invalid backup stream key identifier"));
        }
        let mut key_id_bytes = vec![0u8; key_id_len];
        read_exact_counting(reader, &mut key_id_bytes, &mut ct_hash, &mut ct_bytes)?;
        let key_id = String::from_utf8(key_id_bytes)
            .map_err(|_| CryptoError::Crypto("invalid backup stream key identifier"))?;
        if !valid_key_id(&key_id) {
            return Err(CryptoError::Crypto("invalid backup stream key identifier"));
        }
        if let Some(expected) = expected_key_id
            && key_id != expected
        {
            return Err(CryptoError::Crypto(
                "backup stream key identifier does not match manifest",
            ));
        }

        let mut salt = [0u8; SALT_BYTES];
        read_exact_counting(reader, &mut salt, &mut ct_hash, &mut ct_bytes)?;
        let mut nonce_prefix = [0u8; NONCE_PREFIX_BYTES];
        read_exact_counting(reader, &mut nonce_prefix, &mut ct_hash, &mut ct_bytes)?;

        let master = self.key_bytes(&key_id)?;
        let dek = derive_dek(master, &salt)?;
        let tag_len = aead::AES_256_GCM.tag_len();
        let max_ct_chunk = CHUNK_SIZE + tag_len;
        let mut chunk_buf = Vec::new();
        let mut seq: u64 = 0;

        loop {
            let mut frame_hdr = [0u8; 5];
            if !read_exact_or_eof(reader, &mut frame_hdr)? {
                return Err(CryptoError::Crypto("truncated backup stream"));
            }
            ct_hash.update(frame_hdr);
            ct_bytes = ct_bytes
                .checked_add(5)
                .ok_or(CryptoError::Crypto("backup ciphertext size overflow"))?;

            let flags = frame_hdr[0];
            let is_final = match flags {
                FLAG_INTERMEDIATE => false,
                FLAG_FINAL => true,
                _ => return Err(CryptoError::Crypto("invalid backup chunk flags")),
            };
            let ct_len =
                u32::from_be_bytes([frame_hdr[1], frame_hdr[2], frame_hdr[3], frame_hdr[4]])
                    as usize;
            if ct_len < tag_len || ct_len > max_ct_chunk {
                return Err(CryptoError::Crypto("invalid backup chunk length"));
            }

            chunk_buf.resize(ct_len, 0);
            read_exact_counting(reader, &mut chunk_buf, &mut ct_hash, &mut ct_bytes)?;

            let nonce = chunk_nonce(&nonce_prefix, seq);
            let aad = build_aad(backup_run_id, artifact_role, &key_id, seq, is_final);
            let plain = dek
                .open_in_place(nonce, aead::Aad::from(&aad), &mut chunk_buf)
                .map_err(|_| CryptoError::Crypto("backup chunk authentication failed"))?;
            pt_hash.update(&*plain);
            pt_bytes = pt_bytes
                .checked_add(plain.len() as u64)
                .ok_or(CryptoError::Crypto("backup plaintext size overflow"))?;
            writer.write_all(plain)?;

            if is_final {
                // Strictly require EOF immediately after the final frame.
                let mut extra = [0u8; 1];
                if reader.read(&mut extra)? != 0 {
                    return Err(CryptoError::Crypto(
                        "unexpected trailing bytes after final backup chunk",
                    ));
                }
                break;
            }
            seq = seq
                .checked_add(1)
                .ok_or(CryptoError::Crypto("backup chunk sequence overflow"))?;
        }

        writer.flush()?;
        Ok(DecryptedStats {
            key_id,
            plaintext_bytes: pt_bytes,
            plaintext_sha256: pt_hash.finalize().into(),
            ciphertext_bytes: ct_bytes,
            ciphertext_sha256: ct_hash.finalize().into(),
        })
    }
}

/// Cryptographic summary of one encrypted `OMBKUP01` stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedStats {
    pub key_id: String,
    pub plaintext_bytes: u64,
    pub plaintext_sha256: [u8; 32],
    pub ciphertext_bytes: u64,
    pub ciphertext_sha256: [u8; 32],
}

/// Cryptographic summary of one decrypted & verified `OMBKUP01` stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecryptedStats {
    pub key_id: String,
    pub plaintext_bytes: u64,
    pub plaintext_sha256: [u8; 32],
    pub ciphertext_bytes: u64,
    pub ciphertext_sha256: [u8; 32],
}

/// Streaming `Write` adapter that encrypts plaintext directly into `OMBKUP01` chunks without
/// buffering full payloads in memory or writing plaintext to disk.
pub struct StreamEncryptor<'a> {
    writer: &'a mut dyn Write,
    dek: aead::LessSafeKey,
    backup_run_id: String,
    artifact_role: String,
    key_id: String,
    nonce_prefix: [u8; NONCE_PREFIX_BYTES],
    seq: u64,
    pending: Vec<u8>,
    pt_hash: Sha256,
    ct_hash: Sha256,
    pt_bytes: u64,
    ct_bytes: u64,
    finished: bool,
}

impl<'a> StreamEncryptor<'a> {
    pub fn start(
        keyring: &BackupKeyRing,
        backup_run_id: &str,
        artifact_role: &str,
        writer: &'a mut dyn Write,
    ) -> Result<Self, CryptoError> {
        let key_id = keyring.active_key_id().to_owned();
        let master = keyring.key_bytes(&key_id)?;
        let rng = SystemRandom::new();
        let mut salt = [0u8; SALT_BYTES];
        let mut nonce_prefix = [0u8; NONCE_PREFIX_BYTES];
        rng.fill(&mut salt).map_err(|_| CryptoError::Random)?;
        rng.fill(&mut nonce_prefix)
            .map_err(|_| CryptoError::Random)?;
        let dek = derive_dek(master, &salt)?;

        let mut ct_hash = Sha256::new();
        let mut ct_bytes = 0u64;
        let key_id_len = u16::try_from(key_id.len())
            .map_err(|_| CryptoError::Configuration("invalid backup key identifier"))?;
        write_counting(writer, STREAM_MAGIC, &mut ct_hash, &mut ct_bytes)?;
        write_counting(
            writer,
            &key_id_len.to_be_bytes(),
            &mut ct_hash,
            &mut ct_bytes,
        )?;
        write_counting(writer, key_id.as_bytes(), &mut ct_hash, &mut ct_bytes)?;
        write_counting(writer, &salt, &mut ct_hash, &mut ct_bytes)?;
        write_counting(writer, &nonce_prefix, &mut ct_hash, &mut ct_bytes)?;

        Ok(Self {
            writer,
            dek,
            backup_run_id: backup_run_id.to_owned(),
            artifact_role: artifact_role.to_owned(),
            key_id,
            nonce_prefix,
            seq: 0,
            pending: Vec::with_capacity(CHUNK_SIZE + aead::AES_256_GCM.tag_len()),
            pt_hash: Sha256::new(),
            ct_hash,
            pt_bytes: 0,
            ct_bytes,
            finished: false,
        })
    }

    fn flush_chunk(&mut self, is_final: bool) -> Result<(), CryptoError> {
        let flags = if is_final {
            FLAG_FINAL
        } else {
            FLAG_INTERMEDIATE
        };
        self.pt_hash.update(&self.pending);
        self.pt_bytes = self
            .pt_bytes
            .checked_add(self.pending.len() as u64)
            .ok_or(CryptoError::Crypto("backup plaintext size overflow"))?;

        let nonce = chunk_nonce(&self.nonce_prefix, self.seq);
        let aad = build_aad(
            &self.backup_run_id,
            &self.artifact_role,
            &self.key_id,
            self.seq,
            is_final,
        );
        self.dek
            .seal_in_place_append_tag(nonce, aead::Aad::from(&aad), &mut self.pending)
            .map_err(|_| CryptoError::Crypto("backup chunk encryption failed"))?;

        let ct_len = u32::try_from(self.pending.len())
            .map_err(|_| CryptoError::Crypto("backup chunk length overflow"))?;
        let mut frame_hdr = [0u8; 5];
        frame_hdr[0] = flags;
        frame_hdr[1..5].copy_from_slice(&ct_len.to_be_bytes());
        write_counting(
            self.writer,
            &frame_hdr,
            &mut self.ct_hash,
            &mut self.ct_bytes,
        )?;
        write_counting(
            self.writer,
            &self.pending,
            &mut self.ct_hash,
            &mut self.ct_bytes,
        )?;
        self.pending.clear();
        if !is_final {
            self.seq = self
                .seq
                .checked_add(1)
                .ok_or(CryptoError::Crypto("backup chunk sequence overflow"))?;
        }
        Ok(())
    }

    pub fn finish(mut self) -> Result<EncryptedStats, CryptoError> {
        if self.finished {
            return Err(CryptoError::Crypto("backup encryptor already finished"));
        }
        self.flush_chunk(true)?;
        self.writer.flush()?;
        self.finished = true;
        Ok(EncryptedStats {
            key_id: self.key_id,
            plaintext_bytes: self.pt_bytes,
            plaintext_sha256: self.pt_hash.finalize().into(),
            ciphertext_bytes: self.ct_bytes,
            ciphertext_sha256: self.ct_hash.finalize().into(),
        })
    }
}

impl Write for StreamEncryptor<'_> {
    fn write(&mut self, mut buf: &[u8]) -> io::Result<usize> {
        let total = buf.len();
        while !buf.is_empty() {
            // Keep at least one byte or flush strictly when > CHUNK_SIZE so the last chunk
            // always carries the final flag (even for exact multiples of CHUNK_SIZE).
            if self.pending.len() == CHUNK_SIZE {
                self.flush_chunk(false)
                    .map_err(|e| io::Error::other(e.to_string()))?;
            }
            let avail = CHUNK_SIZE - self.pending.len();
            let take = avail.min(buf.len());
            self.pending.extend_from_slice(&buf[..take]);
            buf = &buf[take..];
        }
        Ok(total)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

fn derive_dek(master: &[u8], salt: &[u8; SALT_BYTES]) -> Result<aead::LessSafeKey, CryptoError> {
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, salt).extract(master);
    let okm = prk
        .expand(&[HKDF_INFO], &aead::AES_256_GCM)
        .map_err(|_| CryptoError::Crypto("backup key derivation failed"))?;
    Ok(aead::LessSafeKey::new(aead::UnboundKey::from(okm)))
}

fn chunk_nonce(prefix: &[u8; NONCE_PREFIX_BYTES], seq: u64) -> aead::Nonce {
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(prefix);
    nonce[4..].copy_from_slice(&seq.to_be_bytes());
    aead::Nonce::assume_unique_for_key(nonce)
}

fn build_aad(
    backup_run_id: &str,
    artifact_role: &str,
    key_id: &str,
    chunk_seq: u64,
    is_final: bool,
) -> Vec<u8> {
    let seq_bytes = chunk_seq.to_be_bytes();
    let final_byte = [u8::from(is_final)];
    runs::identity(
        AAD_DOMAIN,
        &[
            backup_run_id.as_bytes(),
            artifact_role.as_bytes(),
            key_id.as_bytes(),
            &seq_bytes,
            &final_byte,
        ],
    )
}

fn write_counting(
    writer: &mut dyn Write,
    bytes: &[u8],
    hash: &mut Sha256,
    count: &mut u64,
) -> Result<(), CryptoError> {
    writer.write_all(bytes)?;
    hash.update(bytes);
    *count = count
        .checked_add(bytes.len() as u64)
        .ok_or(CryptoError::Crypto("backup stream size overflow"))?;
    Ok(())
}

fn read_exact_counting(
    reader: &mut dyn Read,
    buf: &mut [u8],
    hash: &mut Sha256,
    count: &mut u64,
) -> Result<(), CryptoError> {
    let mut off = 0;
    while off < buf.len() {
        let n = reader.read(&mut buf[off..])?;
        if n == 0 {
            return Err(CryptoError::Crypto("unexpected EOF in backup stream"));
        }
        off += n;
    }
    hash.update(&*buf);
    *count = count
        .checked_add(buf.len() as u64)
        .ok_or(CryptoError::Crypto("backup stream size overflow"))?;
    Ok(())
}

/// Returns `Ok(true)` if `buf` was completely filled, `Ok(false)` on clean EOF at byte 0, or
/// `Err` on partial frame truncation.
fn read_exact_or_eof(reader: &mut dyn Read, buf: &mut [u8]) -> Result<bool, CryptoError> {
    let mut off = 0;
    while off < buf.len() {
        let n = reader.read(&mut buf[off..])?;
        if n == 0 {
            return if off == 0 {
                Ok(false)
            } else {
                Err(CryptoError::Crypto("truncated backup chunk header"))
            };
        }
        off += n;
    }
    Ok(true)
}

fn read_full_chunk(reader: &mut dyn Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut off = 0;
    while off < buf.len() {
        let n = reader.read(&mut buf[off..])?;
        if n == 0 {
            break;
        }
        off += n;
    }
    Ok(off)
}

pub(crate) fn file_dev_ino(path: &Path) -> Option<(u64, u64)> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        fs::metadata(path).ok().map(|m| (m.dev(), m.ino()))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

type DevIno = (u64, u64);

fn read_owner_only_file(
    path: &Path,
    limit: usize,
) -> Result<(Vec<u8>, Option<DevIno>), CryptoError> {
    if !path.is_absolute() {
        return Err(CryptoError::Configuration(
            "backup keyring path must be absolute",
        ));
    }
    let check_meta = |m: &fs::Metadata| -> Result<Option<(u64, u64)>, CryptoError> {
        if !m.is_file() || m.len() > limit as u64 {
            return Err(CryptoError::Configuration("invalid backup keyring file"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let perm = m.permissions().mode() & 0o777;
            if (perm & 0o077) != 0 || (perm & 0o111) != 0 {
                return Err(CryptoError::Configuration(
                    "backup keyring file must be owner-only (0400 or 0600)",
                ));
            }
            Ok(Some((m.dev(), m.ino())))
        }
        #[cfg(not(unix))]
        {
            Ok(None)
        }
    };
    let meta = fs::metadata(path)
        .map_err(|_| CryptoError::Configuration("backup keyring file unreadable"))?;
    check_meta(&meta)?;
    let file = fs::File::open(path)
        .map_err(|_| CryptoError::Configuration("backup keyring file unreadable"))?;
    let opened_meta = file
        .metadata()
        .map_err(|_| CryptoError::Configuration("backup keyring file unreadable"))?;
    let dev_ino = check_meta(&opened_meta)?;
    let mut bytes = Vec::with_capacity(limit.min(KEY_BYTES) + 1);
    match file.take(limit as u64 + 1).read_to_end(&mut bytes) {
        Ok(len) if len <= limit => Ok((bytes, dev_ino)),
        _ => {
            drop(SharedSecret::from(bytes));
            Err(CryptoError::Configuration("invalid backup keyring file"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn test_ring() -> BackupKeyRing {
        BackupKeyRing::new(
            "bk-v2".to_owned(),
            vec![
                ("bk-v1".to_owned(), [0x11; 32]),
                ("bk-v2".to_owned(), [0x22; 32]),
            ],
        )
        .unwrap()
    }

    #[test]
    fn ombkup01_round_trip_handles_empty_single_and_multi_chunk_streams() {
        let ring = test_ring();
        let run_id = "11111111-1111-4111-8111-111111111111";
        for len in [
            0usize,
            1,
            17,
            CHUNK_SIZE,
            CHUNK_SIZE + 1,
            CHUNK_SIZE * 2 + 513,
        ] {
            let plain: Vec<u8> = (0..len).map(|i| ((i * 31 + 7) & 0xff) as u8).collect();
            let mut ct = Vec::new();
            let enc = ring
                .encrypt_stream(run_id, "pg_dump", &mut Cursor::new(&plain), &mut ct)
                .unwrap();
            assert_eq!(enc.key_id, "bk-v2");
            assert_eq!(enc.plaintext_bytes, len as u64);
            assert_eq!(enc.ciphertext_bytes, ct.len() as u64);

            let mut out = Vec::new();
            let dec = ring
                .decrypt_stream(
                    run_id,
                    "pg_dump",
                    Some("bk-v2"),
                    &mut Cursor::new(&ct),
                    &mut out,
                )
                .unwrap();
            assert_eq!(out, plain);
            assert_eq!(dec.plaintext_sha256, enc.plaintext_sha256);
            assert_eq!(dec.ciphertext_sha256, enc.ciphertext_sha256);
        }
    }

    #[test]
    fn ombkup01_rejects_tamper_truncation_trailing_bytes_role_swap_and_wrong_key() {
        let ring = test_ring();
        let run_id = "11111111-1111-4111-8111-111111111111";
        let plain = vec![0xab; CHUNK_SIZE + 128];
        let mut ct = Vec::new();
        ring.encrypt_stream(run_id, "artifacts", &mut Cursor::new(&plain), &mut ct)
            .unwrap();

        // Tamper 1 bit in ciphertext.
        let mut tampered = ct.clone();
        let mid = tampered.len() - 10;
        tampered[mid] ^= 0x01;
        assert!(
            ring.decrypt_stream(
                run_id,
                "artifacts",
                None,
                &mut Cursor::new(&tampered),
                &mut Vec::new()
            )
            .is_err()
        );

        // Truncate ciphertext.
        let truncated = &ct[..ct.len() - 1];
        assert!(
            ring.decrypt_stream(
                run_id,
                "artifacts",
                None,
                &mut Cursor::new(truncated),
                &mut Vec::new()
            )
            .is_err()
        );

        // Append trailing byte after final chunk.
        let mut trailing = ct.clone();
        trailing.push(0x00);
        assert!(
            ring.decrypt_stream(
                run_id,
                "artifacts",
                None,
                &mut Cursor::new(&trailing),
                &mut Vec::new()
            )
            .is_err()
        );

        // Swap artifact role AAD.
        assert!(
            ring.decrypt_stream(
                run_id,
                "pg_dump",
                None,
                &mut Cursor::new(&ct),
                &mut Vec::new()
            )
            .is_err()
        );

        // Swap backup_run_id AAD.
        assert!(
            ring.decrypt_stream(
                "22222222-2222-4222-8222-222222222222",
                "artifacts",
                None,
                &mut Cursor::new(&ct),
                &mut Vec::new()
            )
            .is_err()
        );

        // Wrong keyring without bk-v2.
        let other =
            BackupKeyRing::new("bk-v1".to_owned(), vec![("bk-v1".to_owned(), [0x11; 32])]).unwrap();
        assert!(matches!(
            other.decrypt_stream(
                run_id,
                "artifacts",
                None,
                &mut Cursor::new(&ct),
                &mut Vec::new()
            ),
            Err(CryptoError::UnknownKey)
        ));
    }

    #[test]
    fn keyring_rejects_zero_duplicate_and_world_readable_files() {
        assert!(BackupKeyRing::new("k1".into(), vec![("k1".into(), [0u8; 32])]).is_err());
        assert!(
            BackupKeyRing::new(
                "k1".into(),
                vec![("k1".into(), [0x42; 32]), ("k2".into(), [0x42; 32])]
            )
            .is_err()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut rnd = [0u8; 4];
            SystemRandom::new().fill(&mut rnd).unwrap();
            let dir = std::env::temp_dir().join(format!(
                "om-backup-ring-test-{}-{:02x}{:02x}{:02x}{:02x}",
                std::process::id(),
                rnd[0],
                rnd[1],
                rnd[2],
                rnd[3],
            ));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            let key_path = dir.join("bk1.key");
            let cfg_path = dir.join("keyring.json");
            fs::write(&key_path, [0x55u8; 32]).unwrap();
            fs::set_permissions(&key_path, fs::Permissions::from_mode(0o644)).unwrap();
            fs::write(
                &cfg_path,
                serde_json::json!({
                    "version": 1,
                    "active_key_id": "bk1",
                    "keys": [{"id": "bk1", "file": key_path.to_str().unwrap()}]
                })
                .to_string(),
            )
            .unwrap();
            fs::set_permissions(&cfg_path, fs::Permissions::from_mode(0o600)).unwrap();
            // World-readable key file refused.
            assert!(BackupKeyRing::load_from_config(&cfg_path).is_err());

            // 0600 key file accepted, and vault overlap refused.
            fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();
            let ring = BackupKeyRing::load_from_config(&cfg_path).unwrap();
            assert_eq!(ring.active_key_id(), "bk1");
            assert!(ring.verify_distinct_from_vault_config(&cfg_path).is_err());

            // Separate vault config with identical key bytes also refused.
            let vkey = dir.join("vault.key");
            let vcfg = dir.join("vault.json");
            fs::write(&vkey, [0x55u8; 32]).unwrap();
            fs::set_permissions(&vkey, fs::Permissions::from_mode(0o600)).unwrap();
            fs::write(
                &vcfg,
                serde_json::json!({
                    "version": 1,
                    "active_key_id": "vk1",
                    "keys": [{"id": "vk1", "file": vkey.to_str().unwrap()}]
                })
                .to_string(),
            )
            .unwrap();
            assert!(ring.verify_distinct_from_vault_config(&vcfg).is_err());
            let _ = fs::remove_dir_all(&dir);
        }
    }
}
