use super::*;
use anyhow::{anyhow, bail, Context};
use rand::Rng;
use serde_derive::{Deserialize, Serialize};
use sodiumoxide::{
    base64,
    crypto::{aead::xchacha20poly1305_ietf as aead, pwhash::argon2id13},
};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

const PROFILE_FORMAT: &str = "masterdesk-portable-profile";
const PROFILE_VERSION: u32 = 1;
const PROFILE_AAD: &[u8] = b"MasterDesk portable profile v1; Argon2id; XChaCha20-Poly1305";
const PROFILE_KDF: &str = "argon2id13";
const PROFILE_CIPHER: &str = "xchacha20poly1305-ietf";
const PROFILE_KDF_OPS_LIMIT: usize = 3;
const PROFILE_KDF_MEM_LIMIT: usize = 64 * 1024 * 1024;
const PROFILE_MAX_FILE_BYTES: u64 = 96 * 1024 * 1024;
const PROFILE_MAX_PAYLOAD_BYTES: usize = 64 * 1024 * 1024;
const PROFILE_MAX_PEERS: usize = 10_000;
const PROFILE_MAX_PEER_ID_CHARS: usize = 256;
const MASTER_PASSWORD_MIN_CHARS: usize = 12;
const MASTER_PASSWORD_MAX_CHARS: usize = 128;
const MASTER_PASSWORD_SPECIALS: &str = "!@#$%^&*(),.?\":{}|<>";

struct SensitiveBytes(Vec<u8>);

impl AsRef<[u8]> for SensitiveBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::ops::Deref for SensitiveBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl Drop for SensitiveBytes {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileEnvelope {
    format: String,
    version: u32,
    kdf: String,
    kdf_ops_limit: usize,
    kdf_mem_limit: usize,
    cipher: String,
    salt: String,
    nonce: String,
    ciphertext: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PortableProfile {
    schema_version: u32,
    exported_at_unix_ms: u64,
    app_name: String,
    config2: Config2,
    local_config: LocalConfig,
    user_default_config: UserDefaultConfig,
    peers: Vec<PortablePeer>,
    address_book: Ab,
    group: Group,
    lan_peers: LanPeers,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PortablePeer {
    id: String,
    modified_at_unix_ms: u64,
    alias: String,
    config: PeerConfig,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProfileTransferSummary {
    pub peer_count: usize,
    pub address_book_entry_count: usize,
    pub group_peer_count: usize,
}

pub fn validate_profile_master_password(password: &str) -> Result<()> {
    let length = password.chars().count();
    if !(MASTER_PASSWORD_MIN_CHARS..=MASTER_PASSWORD_MAX_CHARS).contains(&length) {
        bail!(
            "Master password must contain between {MASTER_PASSWORD_MIN_CHARS} and {MASTER_PASSWORD_MAX_CHARS} characters"
        );
    }
    if password.trim() != password || password.chars().any(char::is_control) {
        bail!(
            "Master password must not start or end with whitespace or contain control characters"
        );
    }
    if !password.chars().any(char::is_uppercase) {
        bail!("Master password must contain an uppercase letter");
    }
    if !password.chars().any(char::is_lowercase) {
        bail!("Master password must contain a lowercase letter");
    }
    if !password.chars().any(|character| character.is_ascii_digit()) {
        bail!("Master password must contain a digit");
    }
    if !password
        .chars()
        .any(|character| MASTER_PASSWORD_SPECIALS.contains(character))
    {
        bail!("Master password must contain a special character");
    }
    Ok(())
}

pub fn export_portable_profile(
    path: &str,
    master_password: &str,
) -> Result<ProfileTransferSummary> {
    validate_profile_master_password(master_password)?;
    let profile = build_portable_profile()?;
    let summary = profile_summary(&profile);
    let encoded = encrypt_profile(&profile, master_password)?;
    write_profile_atomically(Path::new(path), &encoded)?;
    Ok(summary)
}

pub fn import_portable_profile(
    path: &str,
    master_password: &str,
) -> Result<ProfileTransferSummary> {
    if master_password.is_empty() {
        bail!("Master password is required");
    }
    let path = Path::new(path);
    let metadata = fs::metadata(path)
        .with_context(|| format!("Failed to inspect profile file '{}'", path.display()))?;
    if !metadata.is_file() {
        bail!("The selected profile path is not a file");
    }
    if metadata.len() > PROFILE_MAX_FILE_BYTES {
        bail!("The selected profile is too large");
    }
    let encoded = fs::read(path)
        .with_context(|| format!("Failed to read profile file '{}'", path.display()))?;
    let mut profile = decrypt_profile(&encoded, master_password)?;
    validate_portable_profile(&profile)?;
    sanitize_imported_profile(&mut profile);
    let summary = profile_summary(&profile);
    apply_portable_profile(profile)?;
    Ok(summary)
}

fn build_portable_profile() -> Result<PortableProfile> {
    let mut config2 = CONFIG2
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    config2.trusted_devices.clear();
    remove_nonportable_options(&mut config2.options);

    let mut local_config = LOCAL_CONFIG
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    remove_nonportable_options(&mut local_config.options);

    let mut user_default_config = USER_DEFAULT_CONFIG
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .0
        .clone();
    remove_nonportable_options(&mut user_default_config.options);

    let mut peers = Vec::new();
    for (id, modified, _) in PeerConfig::get_vec_id_modified_time_path(&None) {
        validate_peer_id(&id)?;
        let config = PeerConfig::load(&id);
        let alias = config.options.get("alias").cloned().unwrap_or_default();
        let modified_at_unix_ms = modified
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis() as u64)
            .unwrap_or_default();
        peers.push(PortablePeer {
            id,
            modified_at_unix_ms,
            alias,
            config,
        });
    }
    if peers.len() > PROFILE_MAX_PEERS {
        bail!("Too many saved peers to export");
    }

    let mut address_book = Ab::load();
    address_book.access_token.clear();
    let mut group = Group::load();
    group.access_token.clear();

    Ok(PortableProfile {
        schema_version: PROFILE_VERSION,
        exported_at_unix_ms: unix_time_ms(SystemTime::now()),
        app_name: APP_NAME
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone(),
        config2,
        local_config,
        user_default_config,
        peers,
        address_book,
        group,
        lan_peers: LanPeers::load(),
    })
}

fn profile_summary(profile: &PortableProfile) -> ProfileTransferSummary {
    ProfileTransferSummary {
        peer_count: profile.peers.len(),
        address_book_entry_count: profile.address_book.ab_entries.len(),
        group_peer_count: profile.group.peers.len(),
    }
}

fn encrypt_profile(profile: &PortableProfile, master_password: &str) -> Result<Vec<u8>> {
    validate_profile_master_password(master_password)?;
    sodiumoxide::init().map_err(|_| anyhow!("Failed to initialize profile encryption"))?;
    let serialized = SensitiveBytes(serde_json::to_vec(profile)?);
    if serialized.len() > PROFILE_MAX_PAYLOAD_BYTES {
        bail!("Profile payload is too large");
    }
    let compressed = SensitiveBytes(zstd::bulk::compress(serialized.as_ref(), 6)?);
    let salt = argon2id13::gen_salt();
    let mut key_bytes = [0u8; aead::KEYBYTES];
    argon2id13::derive_key(
        &mut key_bytes,
        master_password.as_bytes(),
        &salt,
        argon2id13::OpsLimit(PROFILE_KDF_OPS_LIMIT),
        argon2id13::MemLimit(PROFILE_KDF_MEM_LIMIT),
    )
    .map_err(|_| anyhow!("Failed to derive profile encryption key"))?;
    let mut key = aead::Key(key_bytes);
    key_bytes.fill(0);
    let nonce = aead::gen_nonce();
    let ciphertext = aead::seal(compressed.as_ref(), Some(PROFILE_AAD), &nonce, &key);
    key.0.fill(0);

    let envelope = ProfileEnvelope {
        format: PROFILE_FORMAT.to_owned(),
        version: PROFILE_VERSION,
        kdf: PROFILE_KDF.to_owned(),
        kdf_ops_limit: PROFILE_KDF_OPS_LIMIT,
        kdf_mem_limit: PROFILE_KDF_MEM_LIMIT,
        cipher: PROFILE_CIPHER.to_owned(),
        salt: base64::encode(salt.0, base64::Variant::Original),
        nonce: base64::encode(nonce.0, base64::Variant::Original),
        ciphertext: base64::encode(ciphertext, base64::Variant::Original),
    };
    let mut encoded = serde_json::to_vec_pretty(&envelope)?;
    encoded.push(b'\n');
    if encoded.len() as u64 > PROFILE_MAX_FILE_BYTES {
        bail!("Encrypted profile is too large");
    }
    Ok(encoded)
}

fn decrypt_profile(encoded: &[u8], master_password: &str) -> Result<PortableProfile> {
    if encoded.len() as u64 > PROFILE_MAX_FILE_BYTES {
        bail!("The selected profile is too large");
    }
    sodiumoxide::init().map_err(|_| anyhow!("Failed to initialize profile encryption"))?;
    let envelope: ProfileEnvelope =
        serde_json::from_slice(encoded).context("Invalid protected profile envelope")?;
    if envelope.format != PROFILE_FORMAT
        || envelope.version != PROFILE_VERSION
        || envelope.kdf != PROFILE_KDF
        || envelope.kdf_ops_limit != PROFILE_KDF_OPS_LIMIT
        || envelope.kdf_mem_limit != PROFILE_KDF_MEM_LIMIT
        || envelope.cipher != PROFILE_CIPHER
    {
        bail!("Unsupported protected profile format or parameters");
    }
    let salt = base64::decode(envelope.salt, base64::Variant::Original)
        .ok()
        .and_then(|value| argon2id13::Salt::from_slice(&value))
        .ok_or_else(|| anyhow!("Invalid protected profile salt"))?;
    let nonce = base64::decode(envelope.nonce, base64::Variant::Original)
        .ok()
        .and_then(|value| aead::Nonce::from_slice(&value))
        .ok_or_else(|| anyhow!("Invalid protected profile nonce"))?;
    let ciphertext = base64::decode(envelope.ciphertext, base64::Variant::Original)
        .map_err(|_| anyhow!("Invalid protected profile ciphertext"))?;
    if ciphertext.len() > PROFILE_MAX_PAYLOAD_BYTES {
        bail!("Encrypted profile payload is too large");
    }

    let mut key_bytes = [0u8; aead::KEYBYTES];
    argon2id13::derive_key(
        &mut key_bytes,
        master_password.as_bytes(),
        &salt,
        argon2id13::OpsLimit(PROFILE_KDF_OPS_LIMIT),
        argon2id13::MemLimit(PROFILE_KDF_MEM_LIMIT),
    )
    .map_err(|_| anyhow!("Failed to derive profile encryption key"))?;
    let mut key = aead::Key(key_bytes);
    key_bytes.fill(0);
    let compressed = aead::open(&ciphertext, Some(PROFILE_AAD), &nonce, &key)
        .map(SensitiveBytes)
        .map_err(|_| anyhow!("Incorrect master password or damaged protected profile"));
    key.0.fill(0);
    let compressed = compressed?;
    let serialized = SensitiveBytes(
        zstd::bulk::decompress(compressed.as_ref(), PROFILE_MAX_PAYLOAD_BYTES)
            .context("Invalid or oversized protected profile payload")?,
    );
    let profile =
        serde_json::from_slice(serialized.as_ref()).context("Invalid protected profile data")?;
    Ok(profile)
}

fn validate_portable_profile(profile: &PortableProfile) -> Result<()> {
    if profile.schema_version != PROFILE_VERSION {
        bail!("Unsupported profile schema version");
    }
    if profile.app_name.is_empty() || profile.app_name.chars().count() > 128 {
        bail!("Invalid profile application identity");
    }
    if profile.peers.len() > PROFILE_MAX_PEERS {
        bail!("Protected profile contains too many peers");
    }
    let now_with_tolerance = unix_time_ms(SystemTime::now()).saturating_add(24 * 60 * 60 * 1000);
    for peer in &profile.peers {
        validate_peer_id(&peer.id)?;
        if peer.modified_at_unix_ms > now_with_tolerance {
            bail!("Protected profile contains an invalid peer timestamp");
        }
    }
    Ok(())
}

fn validate_peer_id(id: &str) -> Result<()> {
    if id.is_empty()
        || id == "."
        || id == ".."
        || id.chars().count() > PROFILE_MAX_PEER_ID_CHARS
        || id.chars().any(char::is_control)
    {
        bail!("Protected profile contains an invalid peer ID");
    }
    Ok(())
}

fn sanitize_imported_profile(profile: &mut PortableProfile) {
    profile.config2.trusted_devices.clear();
    remove_nonportable_options(&mut profile.config2.options);
    remove_nonportable_options(&mut profile.local_config.options);
    remove_nonportable_options(&mut profile.user_default_config.options);
    profile.address_book.access_token.clear();
    profile.group.access_token.clear();
}

fn is_nonportable_option_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    matches!(
        key.as_str(),
        "2fa" | "bot" | "access_token" | "access-token" | "trusted-devices"
    ) || key.ends_with("_token")
        || key.ends_with("-token")
        || key.ends_with("_secret")
        || key.ends_with("-secret")
        || key.ends_with("_credential")
        || key.ends_with("-credential")
}

fn remove_nonportable_options(options: &mut HashMap<String, String>) {
    options.retain(|key, _| !is_nonportable_option_key(key));
}

fn preserve_target_only_options(
    imported: &mut HashMap<String, String>,
    current: &HashMap<String, String>,
) {
    remove_nonportable_options(imported);
    for (key, value) in current {
        if is_nonportable_option_key(key) {
            imported.insert(key.clone(), value.clone());
        }
    }
}

fn apply_portable_profile(mut profile: PortableProfile) -> Result<()> {
    let current_config2 = CONFIG2
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    preserve_target_only_options(&mut profile.config2.options, &current_config2.options);
    profile.config2.trusted_devices = current_config2.trusted_devices;
    Config2::set(profile.config2);

    {
        let mut current = LOCAL_CONFIG
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        preserve_target_only_options(&mut profile.local_config.options, &current.options);
        *current = profile.local_config;
        current.store();
    }

    {
        let mut current = USER_DEFAULT_CONFIG
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        preserve_target_only_options(&mut profile.user_default_config.options, &current.0.options);
        current.0 = profile.user_default_config;
        current.1 = Instant::now();
        current.0.store();
    }

    for peer in profile.peers {
        peer.config.store(&peer.id);
        if !PeerConfig::set_alias(&peer.id, &peer.alias) {
            bail!("Failed to restore a peer alias");
        }
        let path = PeerConfig::path(&peer.id);
        if !path.is_file() {
            bail!("Failed to restore a peer configuration");
        }
        if peer.modified_at_unix_ms != 0 {
            let seconds = (peer.modified_at_unix_ms / 1000) as i64;
            let nanos = ((peer.modified_at_unix_ms % 1000) * 1_000_000) as u32;
            filetime::set_file_mtime(&path, filetime::FileTime::from_unix_time(seconds, nanos))?;
        }
    }

    let mut current_address_book = Ab::load();
    profile.address_book.access_token = std::mem::take(&mut current_address_book.access_token);
    Ab::store(serde_json::to_string(&profile.address_book)?);

    let mut current_group = Group::load();
    profile.group.access_token = std::mem::take(&mut current_group.access_token);
    Group::store(serde_json::to_string(&profile.group)?);

    LanPeers::store(&profile.lan_peers.peers);
    Ok(())
}

fn write_profile_atomically(path: &Path, data: &[u8]) -> Result<()> {
    if path.as_os_str().is_empty() {
        bail!("Profile export path is empty");
    }
    if path.is_dir() {
        bail!("Profile export path is a directory");
    }
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("Profile export path has no parent directory"))?;
    if !parent.is_dir() {
        bail!("Profile export directory does not exist");
    }

    let mut temporary = PathBuf::from(path);
    temporary.set_extension(format!(
        "mdprofile.{}.{}.tmp",
        std::process::id(),
        rand::thread_rng().gen::<u64>()
    ));
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .with_context(|| {
                format!(
                    "Failed to create temporary profile file '{}'",
                    temporary.display()
                )
            })?;
        file.write_all(data)?;
        file.sync_all()?;
        drop(file);
        replace_file(&temporary, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(target_os = "windows")]
fn replace_file(source: &Path, destination: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use winapi::um::winbase::{MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH};

    let source: Vec<u16> = source
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let destination: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let replaced = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if replaced == 0 {
        return Err(anyhow!(
            "Failed to replace protected profile file: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn replace_file(source: &Path, destination: &Path) -> Result<()> {
    fs::rename(source, destination)?;
    Ok(())
}

fn unix_time_ms(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_profile() -> PortableProfile {
        let mut config2 = Config2::default();
        config2
            .options
            .insert("2fa".to_owned(), "do-not-export".to_owned());
        config2.options.insert(
            "default-connect-password".to_owned(),
            "export-this-password".to_owned(),
        );
        PortableProfile {
            schema_version: PROFILE_VERSION,
            exported_at_unix_ms: 1,
            app_name: "MasterDesk".to_owned(),
            config2,
            local_config: LocalConfig::default(),
            user_default_config: UserDefaultConfig::default(),
            peers: vec![PortablePeer {
                id: "123456789".to_owned(),
                modified_at_unix_ms: 1,
                alias: "Office".to_owned(),
                config: PeerConfig {
                    password: b"saved-password-hash".to_vec(),
                    ..Default::default()
                },
            }],
            address_book: Ab::default(),
            group: Group::default(),
            lan_peers: LanPeers::default(),
        }
    }

    #[test]
    fn master_password_complexity_is_enforced() {
        for invalid in [
            "Short1!",
            "alllowercase1!",
            "ALLUPPERCASE1!",
            "NoDigitsHere!",
            "NoSpecial1234",
            " Leading1!Password",
        ] {
            assert!(
                validate_profile_master_password(invalid).is_err(),
                "{}",
                invalid
            );
        }
        assert!(validate_profile_master_password("StrongMaster1!").is_ok());
    }

    #[test]
    fn protected_profile_round_trip_rejects_wrong_password_and_tampering() {
        let mut profile = sample_profile();
        sanitize_imported_profile(&mut profile);
        let encoded = encrypt_profile(&profile, "StrongMaster1!").unwrap();
        let decoded = decrypt_profile(&encoded, "StrongMaster1!").unwrap();
        assert_eq!(decoded.peers.len(), 1);
        assert_eq!(decoded.peers[0].config.password, b"saved-password-hash");
        assert!(decrypt_profile(&encoded, "WrongMaster1!").is_err());

        let mut envelope: ProfileEnvelope = serde_json::from_slice(&encoded).unwrap();
        envelope.ciphertext.push('A');
        let tampered = serde_json::to_vec(&envelope).unwrap();
        assert!(decrypt_profile(&tampered, "StrongMaster1!").is_err());
    }

    #[test]
    fn export_sanitizer_excludes_tokens_but_keeps_saved_connection_passwords() {
        let mut profile = sample_profile();
        profile
            .local_config
            .options
            .insert("access_token".to_owned(), "do-not-export".to_owned());
        sanitize_imported_profile(&mut profile);
        assert!(!profile.config2.options.contains_key("2fa"));
        assert!(!profile.local_config.options.contains_key("access_token"));
        assert_eq!(
            profile.config2.options.get("default-connect-password"),
            Some(&"export-this-password".to_owned())
        );
    }

    #[test]
    fn peer_ids_cannot_escape_the_profile_directory() {
        for invalid in ["", ".", "..", "bad\nid"] {
            assert!(validate_peer_id(invalid).is_err());
        }
        assert!(validate_peer_id("192.168.7.14:21118").is_ok());
    }
}
