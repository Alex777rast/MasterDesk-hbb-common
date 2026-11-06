use crate::config::Config;
use sodiumoxide::{base64, crypto::secretbox};
#[cfg(target_os = "windows")]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::{
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

/// MasterDesk keeps the temporary password stable for three hours so it can be
/// shared with a technician without changing after every completed session.
/// Manual refreshes and brute-force protection may still rotate it earlier.
pub const TEMPORARY_PASSWORD_ROTATION_INTERVAL: Duration = Duration::from_secs(3 * 60 * 60);
struct TemporaryPasswordState {
    value: String,
    generated_at: Instant,
}

impl TemporaryPasswordState {
    fn new() -> Self {
        Self {
            value: get_auto_password(),
            generated_at: Instant::now(),
        }
    }

    fn rotate(&mut self, now: Instant) {
        self.value = get_auto_password();
        self.generated_at = now;
    }

    fn rotate_if_due(&mut self, now: Instant) -> bool {
        if !temporary_password_rotation_due(self.generated_at, now) {
            return false;
        }
        self.rotate(now);
        true
    }
}

lazy_static::lazy_static! {
    static ref TEMPORARY_PASSWORD: Arc<RwLock<TemporaryPasswordState>> =
        Arc::new(RwLock::new(TemporaryPasswordState::new()));
}

#[cfg(target_os = "windows")]
static TEMPORARY_PASSWORD_GUI_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);

/// Keeps temporary-password authentication enabled for exactly the lifetime of
/// an authenticated main-GUI IPC connection. A polling delay must never change
/// an incoming request from password authentication to click approval.
#[cfg(target_os = "windows")]
pub struct TemporaryPasswordGuiLease;

#[cfg(target_os = "windows")]
impl Drop for TemporaryPasswordGuiLease {
    fn drop(&mut self) {
        let _ = TEMPORARY_PASSWORD_GUI_CONNECTIONS.fetch_update(
            Ordering::SeqCst,
            Ordering::SeqCst,
            |current| current.checked_sub(1),
        );
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VerificationMethod {
    OnlyUseTemporaryPassword,
    OnlyUsePermanentPassword,
    UseBothPasswords,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApproveMode {
    Both,
    Password,
    Click,
}

fn get_auto_password() -> String {
    let len = temporary_password_length();
    if Config::get_bool_option(crate::config::keys::OPTION_ALLOW_NUMERNIC_ONE_TIME_PASSWORD) {
        Config::get_auto_numeric_password(len)
    } else {
        Config::get_auto_password(len)
    }
}

fn temporary_password_rotation_due(generated_at: Instant, now: Instant) -> bool {
    now.checked_duration_since(generated_at)
        .map(|elapsed| elapsed >= TEMPORARY_PASSWORD_ROTATION_INTERVAL)
        .unwrap_or(false)
}

// Should only be called in server
pub fn update_temporary_password() {
    TEMPORARY_PASSWORD
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .rotate(Instant::now());
}

// Should only be called in server
pub fn temporary_password() -> String {
    let mut state = TEMPORARY_PASSWORD
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if state.rotate_if_due(Instant::now()) {
        log::info!("Temporary password rotated after the three-hour MasterDesk interval");
    }
    state.value.clone()
}

#[cfg(target_os = "windows")]
pub fn acquire_temporary_password_gui_lease() -> TemporaryPasswordGuiLease {
    TEMPORARY_PASSWORD_GUI_CONNECTIONS.fetch_add(1, Ordering::SeqCst);
    TemporaryPasswordGuiLease
}

#[inline]
pub fn temporary_password_available_for_auth() -> bool {
    #[cfg(target_os = "windows")]
    {
        return TEMPORARY_PASSWORD_GUI_CONNECTIONS.load(Ordering::SeqCst) != 0;
    }
    #[cfg(not(target_os = "windows"))]
    {
        true
    }
}

fn verification_method() -> VerificationMethod {
    let method = Config::get_option("verification-method");
    if method == "use-temporary-password" {
        VerificationMethod::OnlyUseTemporaryPassword
    } else if method == "use-permanent-password" {
        VerificationMethod::OnlyUsePermanentPassword
    } else {
        VerificationMethod::UseBothPasswords // default
    }
}

pub fn temporary_password_length() -> usize {
    let length = Config::get_option("temporary-password-length");
    if length == "8" {
        8
    } else if length == "10" {
        10
    } else {
        6 // default
    }
}

pub fn temporary_enabled() -> bool {
    verification_method() != VerificationMethod::OnlyUsePermanentPassword
}

pub fn permanent_enabled() -> bool {
    verification_method() != VerificationMethod::OnlyUseTemporaryPassword
}

pub fn has_valid_password() -> bool {
    temporary_enabled()
        && temporary_password_available_for_auth()
        && !temporary_password().is_empty()
        || permanent_enabled() && Config::has_permanent_password()
}

pub fn approve_mode() -> ApproveMode {
    let mode = Config::get_option("approve-mode");
    if mode == "password" {
        ApproveMode::Password
    } else if mode == "click" {
        ApproveMode::Click
    } else {
        ApproveMode::Both
    }
}

pub fn hide_cm() -> bool {
    approve_mode() == ApproveMode::Password
        && verification_method() == VerificationMethod::OnlyUsePermanentPassword
        && crate::config::option2bool("allow-hide-cm", &Config::get_option("allow-hide-cm"))
}

const VERSION_LEN: usize = 2;
const FORMAT_V1: u8 = 1;
pub const LOCAL_SECRET_ENC_VERSION: &str = "03";
const LEGACY_LOCAL_SECRET_ENC_VERSION: &str = "02";
const LOCAL_SECRET_MIN_ENCODED_BYTES: usize = 16;
const LOCAL_SECRET_ENTROPY_CONTEXT: &[u8] = b"MasterDesk local profile secrets v2";
const LEGACY_LOCAL_SECRET_ENTROPY_CONTEXT: &[u8] = b"MasterDesk local profile secrets v1";

// Check if data is already encrypted by verifying:
// 1) version prefix "00"
// 2) valid base64 payload
// 3) decoded payload length >= secretbox::MACBYTES
//
// We intentionally avoid trying to decrypt here because key mismatch would cause
// false negatives.
// The decoded payload may be either legacy ciphertext or FORMAT_V1 || nonce || ciphertext.
// Reference: secretbox::seal returns ciphertext length = plaintext length + MACBYTES
// https://github.com/sodiumoxide/sodiumoxide/blob/3057acb1a030ad86ed8892a223d64036ab5e8523/src/crypto/secretbox/xsalsa20poly1305.rs#L67
pub(crate) fn is_encrypted(v: &[u8]) -> bool {
    if v.len() <= VERSION_LEN || !v.starts_with(b"00") {
        return false;
    }
    match base64::decode(&v[VERSION_LEN..], base64::Variant::Original) {
        Ok(decoded) => decoded.len() >= sodiumoxide::crypto::secretbox::MACBYTES,
        Err(_) => false,
    }
}

pub(crate) fn is_local_secret_encrypted(v: &[u8]) -> bool {
    if v.len() <= VERSION_LEN
        || !(v.starts_with(LOCAL_SECRET_ENC_VERSION.as_bytes())
            || v.starts_with(LEGACY_LOCAL_SECRET_ENC_VERSION.as_bytes()))
    {
        return false;
    }
    match base64::decode(&v[VERSION_LEN..], base64::Variant::Original) {
        Ok(decoded) => decoded.len() >= LOCAL_SECRET_MIN_ENCODED_BYTES,
        Err(_) => false,
    }
}

/// Encrypts a user-profile secret with an OS-backed, machine-bound key.
///
/// On Windows this uses current-user DPAPI plus entropy derived from the
/// machine UID and the SMBIOS system UUID. The hardware UUID keeps independently
/// running cloned Windows installations isolated even when their copied
/// MachineGuid and user DPAPI material are identical. Failure is closed:
/// plaintext is never returned as a storage value.
pub fn encrypt_local_secret_str(s: &str, max_len: usize) -> Result<String, ()> {
    if s.is_empty() {
        return Ok(String::new());
    }
    if s.chars().count() > max_len {
        return Err(());
    }
    let encrypted = local_secret_crypt(s.as_bytes(), true)?;
    Ok(LOCAL_SECRET_ENC_VERSION.to_owned() + &base64::encode(encrypted, base64::Variant::Original))
}

/// Returns `(plaintext, decrypted, should_migrate)`.
///
/// Current machine-bound ciphertext that cannot be opened is returned as an
/// empty value and is never treated as plaintext. Legacy `00` values and
/// plaintext values request migration when they can be read safely.
pub fn decrypt_local_secret_str(s: &str) -> (String, bool, bool) {
    if s.is_empty() {
        return (String::new(), false, false);
    }
    if s.starts_with(LOCAL_SECRET_ENC_VERSION) {
        if let Ok(decoded) = base64::decode(&s.as_bytes()[VERSION_LEN..], base64::Variant::Original)
        {
            if let Ok(decrypted) = local_secret_crypt(&decoded, false) {
                if let Ok(plaintext) = String::from_utf8(decrypted) {
                    return (plaintext, true, false);
                }
            }
        }
        log::warn!("A machine-bound local secret could not be decrypted; ignoring it");
        return (String::new(), false, false);
    }
    if s.starts_with(LEGACY_LOCAL_SECRET_ENC_VERSION) {
        if let Ok(decoded) = base64::decode(&s.as_bytes()[VERSION_LEN..], base64::Variant::Original)
        {
            if let Ok(decrypted) = legacy_local_secret_crypt(&decoded, false) {
                if let Ok(plaintext) = String::from_utf8(decrypted) {
                    return (plaintext, true, true);
                }
            }
        }
        log::warn!("A legacy machine-bound local secret could not be decrypted; ignoring it");
        return (String::new(), false, false);
    }
    if is_encrypted(s.as_bytes()) {
        let (plaintext, decrypted, _) = decrypt_str_or_original(s, "00");
        if decrypted {
            return (plaintext, true, true);
        }
        log::warn!("A legacy local secret could not be decrypted; ignoring it");
        return (String::new(), false, false);
    }
    (s.to_owned(), false, true)
}

pub fn encrypt_local_secret_vec(v: &[u8], max_len: usize) -> Result<Vec<u8>, ()> {
    if v.is_empty() {
        return Ok(Vec::new());
    }
    if v.len() > max_len {
        return Err(());
    }
    let encrypted = local_secret_crypt(v, true)?;
    let mut output = LOCAL_SECRET_ENC_VERSION.as_bytes().to_vec();
    output.extend(base64::encode(encrypted, base64::Variant::Original).into_bytes());
    Ok(output)
}

pub fn decrypt_local_secret_vec(v: &[u8]) -> (Vec<u8>, bool, bool) {
    if v.is_empty() {
        return (Vec::new(), false, false);
    }
    if v.starts_with(LOCAL_SECRET_ENC_VERSION.as_bytes()) {
        if let Ok(decoded) = base64::decode(&v[VERSION_LEN..], base64::Variant::Original) {
            if let Ok(decrypted) = local_secret_crypt(&decoded, false) {
                return (decrypted, true, false);
            }
        }
        log::warn!("A machine-bound local secret could not be decrypted; ignoring it");
        return (Vec::new(), false, false);
    }
    if v.starts_with(LEGACY_LOCAL_SECRET_ENC_VERSION.as_bytes()) {
        if let Ok(decoded) = base64::decode(&v[VERSION_LEN..], base64::Variant::Original) {
            if let Ok(decrypted) = legacy_local_secret_crypt(&decoded, false) {
                return (decrypted, true, true);
            }
        }
        log::warn!("Legacy machine-bound local secret data could not be decrypted; ignoring it");
        return (Vec::new(), false, false);
    }
    if is_encrypted(v) {
        let (plaintext, decrypted, _) = decrypt_vec_or_original(v, "00");
        if decrypted {
            return (plaintext, true, true);
        }
        log::warn!("A legacy local secret could not be decrypted; ignoring it");
        return (Vec::new(), false, false);
    }
    (v.to_owned(), false, true)
}

#[cfg(target_os = "windows")]
fn local_secret_entropy() -> Result<Vec<u8>, ()> {
    use sha2::{Digest, Sha256};

    let machine_uid = machine_uid::get().map_err(|error| {
        log::error!("Failed to obtain machine UID for local secret protection: {error}");
    })?;
    if machine_uid.is_empty() {
        log::error!("Machine UID for local secret protection is empty");
        return Err(());
    }
    let smbios_uuid = windows_smbios_system_uuid()?;
    let mut digest = Sha256::new();
    digest.update(LOCAL_SECRET_ENTROPY_CONTEXT);
    digest.update(machine_uid.as_bytes());
    digest.update(smbios_uuid);
    Ok(digest.finalize().to_vec())
}

#[cfg(target_os = "windows")]
fn legacy_local_secret_entropy() -> Result<Vec<u8>, ()> {
    use sha2::{Digest, Sha256};

    let machine_uid = machine_uid::get().map_err(|error| {
        log::error!("Failed to obtain machine UID for legacy local secret migration: {error}");
    })?;
    if machine_uid.is_empty() {
        return Err(());
    }
    let mut digest = Sha256::new();
    digest.update(LEGACY_LOCAL_SECRET_ENTROPY_CONTEXT);
    digest.update(machine_uid.as_bytes());
    Ok(digest.finalize().to_vec())
}

#[cfg(target_os = "windows")]
fn windows_smbios_system_uuid() -> Result<[u8; 16], ()> {
    use std::ptr;
    use winapi::um::sysinfoapi::GetSystemFirmwareTable;

    const RAW_SMBIOS_PROVIDER: u32 = u32::from_be_bytes(*b"RSMB");
    let size = unsafe { GetSystemFirmwareTable(RAW_SMBIOS_PROVIDER, 0, ptr::null_mut(), 0) };
    if size < 8 {
        log::error!("SMBIOS data is unavailable for local secret protection");
        return Err(());
    }
    let mut raw = vec![0u8; size as usize];
    let written =
        unsafe { GetSystemFirmwareTable(RAW_SMBIOS_PROVIDER, 0, raw.as_mut_ptr() as *mut _, size) };
    if written != size {
        log::error!("SMBIOS data changed while reading local secret protection identity");
        return Err(());
    }
    parse_raw_smbios_system_uuid(&raw).ok_or_else(|| {
        log::error!("A valid SMBIOS system UUID is unavailable for local secret protection");
    })
}

#[cfg(target_os = "windows")]
fn parse_raw_smbios_system_uuid(raw: &[u8]) -> Option<[u8; 16]> {
    const RAW_HEADER_LEN: usize = 8;
    const STRUCTURE_HEADER_LEN: usize = 4;
    if raw.len() < RAW_HEADER_LEN {
        return None;
    }
    let table_len = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]) as usize;
    let end = RAW_HEADER_LEN.checked_add(table_len)?;
    if end > raw.len() {
        return None;
    }
    let mut position = RAW_HEADER_LEN;
    while position.checked_add(STRUCTURE_HEADER_LEN)? <= end {
        let structure_type = raw[position];
        let structure_len = raw[position + 1] as usize;
        if structure_len < STRUCTURE_HEADER_LEN || position.checked_add(structure_len)? > end {
            return None;
        }
        if structure_type == 1 && structure_len >= 24 {
            let uuid_slice = raw.get(position + 8..position + 24)?;
            if uuid_slice.iter().any(|byte| *byte != 0)
                && uuid_slice.iter().any(|byte| *byte != 0xff)
            {
                let mut uuid = [0u8; 16];
                uuid.copy_from_slice(uuid_slice);
                return Some(uuid);
            }
        }
        if structure_type == 127 {
            return None;
        }
        let mut next = position.checked_add(structure_len)?;
        let mut terminator_found = false;
        while next.checked_add(1)? < end {
            if raw[next] == 0 && raw[next + 1] == 0 {
                next += 2;
                terminator_found = true;
                break;
            }
            next += 1;
        }
        if !terminator_found {
            return None;
        }
        position = next;
    }
    None
}

#[cfg(target_os = "windows")]
fn local_secret_crypt(data: &[u8], encrypt: bool) -> Result<Vec<u8>, ()> {
    let entropy = local_secret_entropy()?;
    local_secret_crypt_with_entropy(data, &entropy, encrypt)
}

#[cfg(target_os = "windows")]
fn legacy_local_secret_crypt(data: &[u8], encrypt: bool) -> Result<Vec<u8>, ()> {
    let entropy = legacy_local_secret_entropy()?;
    local_secret_crypt_with_entropy(data, &entropy, encrypt)
}

#[cfg(target_os = "windows")]
fn local_secret_crypt_with_entropy(
    data: &[u8],
    entropy: &[u8],
    encrypt: bool,
) -> Result<Vec<u8>, ()> {
    use std::{convert::TryFrom, ptr};
    use winapi::um::{
        dpapi::{CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN},
        winbase::LocalFree,
        wincrypt::DATA_BLOB,
    };

    let mut input = data.to_vec();
    let mut entropy = entropy.to_vec();
    let mut input_blob = DATA_BLOB {
        cbData: u32::try_from(input.len()).map_err(|_| ())?,
        pbData: input.as_mut_ptr(),
    };
    let mut entropy_blob = DATA_BLOB {
        cbData: u32::try_from(entropy.len()).map_err(|_| ())?,
        pbData: entropy.as_mut_ptr(),
    };
    let mut output_blob = DATA_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };
    let success = unsafe {
        if encrypt {
            CryptProtectData(
                &mut input_blob,
                ptr::null(),
                &mut entropy_blob,
                ptr::null_mut(),
                ptr::null_mut(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output_blob,
            )
        } else {
            CryptUnprotectData(
                &mut input_blob,
                ptr::null_mut(),
                &mut entropy_blob,
                ptr::null_mut(),
                ptr::null_mut(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output_blob,
            )
        }
    };
    input.fill(0);
    entropy.fill(0);
    if success == 0 || output_blob.pbData.is_null() {
        if !output_blob.pbData.is_null() {
            unsafe {
                LocalFree(output_blob.pbData as _);
            }
        }
        return Err(());
    }
    let output = unsafe {
        let value =
            std::slice::from_raw_parts(output_blob.pbData, output_blob.cbData as usize).to_vec();
        LocalFree(output_blob.pbData as _);
        value
    };
    Ok(output)
}

#[cfg(not(target_os = "windows"))]
fn local_secret_crypt(data: &[u8], encrypt: bool) -> Result<Vec<u8>, ()> {
    symmetric_crypt(data, encrypt)
}

#[cfg(not(target_os = "windows"))]
fn legacy_local_secret_crypt(data: &[u8], encrypt: bool) -> Result<Vec<u8>, ()> {
    symmetric_crypt(data, encrypt)
}

pub fn encrypt_str_or_original(s: &str, version: &str, max_len: usize) -> String {
    if is_encrypted(s.as_bytes()) {
        log::error!("Duplicate encryption!");
        return s.to_owned();
    }
    if s.chars().count() > max_len {
        return String::default();
    }
    if version == "00" {
        if let Ok(s) = encrypt(s.as_bytes()) {
            return version.to_owned() + &s;
        }
    }
    s.to_owned()
}

// String: password
// bool: whether decryption is successful
// bool: whether should store to re-encrypt when load
// note: s.len() return length in bytes, s.chars().count() return char count
//       &[..2] return the left 2 bytes, s.chars().take(2) return the left 2 chars
pub fn decrypt_str_or_original(s: &str, current_version: &str) -> (String, bool, bool) {
    if s.len() > VERSION_LEN {
        if s.starts_with("00") {
            if let Ok(v) = decrypt(s[VERSION_LEN..].as_bytes()) {
                return (
                    String::from_utf8_lossy(&v).to_string(),
                    true,
                    "00" != current_version,
                );
            }
        }
    }

    // For values that already look encrypted (version prefix + base64), avoid
    // repeated store on each load when decryption fails.
    (
        s.to_owned(),
        false,
        !s.is_empty() && !is_encrypted(s.as_bytes()),
    )
}

pub fn encrypt_vec_or_original(v: &[u8], version: &str, max_len: usize) -> Vec<u8> {
    if is_encrypted(v) {
        log::error!("Duplicate encryption!");
        return v.to_owned();
    }
    if v.len() > max_len {
        return vec![];
    }
    if version == "00" {
        if let Ok(s) = encrypt(v) {
            let mut version = version.to_owned().into_bytes();
            version.append(&mut s.into_bytes());
            return version;
        }
    }
    v.to_owned()
}

// Vec<u8>: password
// bool: whether decryption is successful
// bool: whether should store to re-encrypt when load
pub fn decrypt_vec_or_original(v: &[u8], current_version: &str) -> (Vec<u8>, bool, bool) {
    if v.len() > VERSION_LEN {
        let version = String::from_utf8_lossy(&v[..VERSION_LEN]);
        if version == "00" {
            if let Ok(v) = decrypt(&v[VERSION_LEN..]) {
                return (v, true, version != current_version);
            }
        }
    }

    // For values that already look encrypted (version prefix + base64), avoid
    // repeated store on each load when decryption fails.
    (v.to_owned(), false, !v.is_empty() && !is_encrypted(v))
}

fn encrypt(v: &[u8]) -> Result<String, ()> {
    if !v.is_empty() {
        symmetric_crypt(v, true).map(|v| base64::encode(v, base64::Variant::Original))
    } else {
        Err(())
    }
}

fn decrypt(v: &[u8]) -> Result<Vec<u8>, ()> {
    if !v.is_empty() {
        base64::decode(v, base64::Variant::Original).and_then(|v| symmetric_crypt(&v, false))
    } else {
        Err(())
    }
}

pub fn symmetric_crypt(data: &[u8], encrypt: bool) -> Result<Vec<u8>, ()> {
    use sodiumoxide::crypto::secretbox;
    use std::convert::TryInto;

    let uuid = crate::get_uuid();
    let mut keybuf = uuid.clone();
    keybuf.resize(secretbox::KEYBYTES, 0);
    let key = secretbox::Key(keybuf.try_into().map_err(|_| ())?);

    if encrypt {
        let nonce = secretbox::gen_nonce();
        let encrypted = secretbox::seal(data, &nonce, &key);
        let mut output = Vec::with_capacity(1 + nonce.0.len() + encrypted.len());
        output.push(FORMAT_V1);
        output.extend(nonce.0);
        output.extend(encrypted);
        Ok(output)
    } else {
        let res = open_secretbox_payload(data, &key);
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        if res.is_err() {
            // Fallback: try pk if uuid decryption failed (in case encryption used pk due to machine_uid failure)
            if let Some(key_pair) = Config::get_existing_key_pair() {
                let pk = key_pair.1;
                if pk != uuid {
                    let mut keybuf = pk;
                    keybuf.resize(secretbox::KEYBYTES, 0);
                    let pk_key = secretbox::Key(keybuf.try_into().map_err(|_| ())?);
                    return open_secretbox_payload(data, &pk_key);
                }
            }
        }
        res
    }
}

fn open_secretbox_payload(data: &[u8], key: &secretbox::Key) -> Result<Vec<u8>, ()> {
    if data.first() == Some(&FORMAT_V1)
        && data.len() >= 1 + secretbox::NONCEBYTES + secretbox::MACBYTES
    {
        let mut nonce = [0u8; secretbox::NONCEBYTES];
        nonce.copy_from_slice(&data[1..1 + secretbox::NONCEBYTES]);
        let nonce = secretbox::Nonce(nonce);
        if let Ok(decrypted) = secretbox::open(&data[1 + secretbox::NONCEBYTES..], &nonce, key) {
            return Ok(decrypted);
        }
    }

    let legacy_nonce = secretbox::Nonce([0; secretbox::NONCEBYTES]);
    secretbox::open(data, &legacy_nonce, key)
}

mod test {

    #[test]
    fn test() {
        use super::*;
        use rand::{thread_rng, Rng};
        use std::time::Instant;

        let version = "00";
        let max_len = 128;

        println!("test str");
        let data = "1ü1111";
        let encrypted = encrypt_str_or_original(data, version, max_len);
        let (decrypted, succ, store) = decrypt_str_or_original(&encrypted, version);
        println!("data: {data}");
        println!("encrypted: {encrypted}");
        println!("decrypted: {decrypted}");
        assert_eq!(data, decrypted);
        assert_eq!(version, &encrypted[..2]);
        assert!(succ);
        assert!(!store);
        let (_, _, store) = decrypt_str_or_original(&encrypted, "99");
        assert!(store);
        assert!(!decrypt_str_or_original(&decrypted, version).1);
        assert_eq!(
            encrypt_str_or_original(&encrypted, version, max_len),
            encrypted
        );

        println!("test vec");
        let data: Vec<u8> = "1ü1111".as_bytes().to_vec();
        let encrypted = encrypt_vec_or_original(&data, version, max_len);
        let (decrypted, succ, store) = decrypt_vec_or_original(&encrypted, version);
        println!("data: {data:?}");
        println!("encrypted: {encrypted:?}");
        println!("decrypted: {decrypted:?}");
        assert_eq!(data, decrypted);
        assert_eq!(version.as_bytes(), &encrypted[..2]);
        assert!(!store);
        assert!(succ);
        let (_, _, store) = decrypt_vec_or_original(&encrypted, "99");
        assert!(store);
        assert!(!decrypt_vec_or_original(&decrypted, version).1);
        assert_eq!(
            encrypt_vec_or_original(&encrypted, version, max_len),
            encrypted
        );

        println!("test original");
        let data = version.to_string() + "Hello World";
        let (decrypted, succ, store) = decrypt_str_or_original(&data, version);
        assert_eq!(data, decrypted);
        assert!(store);
        assert!(!succ);
        let verbytes = version.as_bytes();
        let data: Vec<u8> = vec![verbytes[0], verbytes[1], 1, 2, 3, 4, 5, 6];
        let (decrypted, succ, store) = decrypt_vec_or_original(&data, version);
        assert_eq!(data, decrypted);
        assert!(store);
        assert!(!succ);
        let (_, succ, store) = decrypt_str_or_original("", version);
        assert!(!store);
        assert!(!succ);
        let (_, succ, store) = decrypt_vec_or_original(&[], version);
        assert!(!store);
        assert!(!succ);
        let data = "1ü1111";
        assert_eq!(decrypt_str_or_original(data, version).0, data);
        let data: Vec<u8> = "1ü1111".as_bytes().to_vec();
        assert_eq!(decrypt_vec_or_original(&data, version).0, data);

        // Base64-shaped "00" prefixed values shorter than MACBYTES are treated
        // as original/plain values and should be stored.
        let data = "00YWJjZA==";
        let (decrypted, succ, store) = decrypt_str_or_original(data, version);
        assert_eq!(decrypted, data);
        assert!(!succ);
        assert!(store);
        let data = b"00YWJjZA==".to_vec();
        let (decrypted, succ, store) = decrypt_vec_or_original(&data, version);
        assert_eq!(decrypted, data);
        assert!(!succ);
        assert!(store);

        // When decoded length reaches MACBYTES, it is treated as encrypted-like
        // and should not trigger repeated store.
        let exact_mac = vec![0u8; sodiumoxide::crypto::secretbox::MACBYTES];
        let exact_mac_b64 =
            sodiumoxide::base64::encode(&exact_mac, sodiumoxide::base64::Variant::Original);
        let data = format!("00{exact_mac_b64}");
        let (_, succ, store) = decrypt_str_or_original(&data, version);
        assert!(!succ);
        assert!(!store);
        let data = data.into_bytes();
        let (_, succ, store) = decrypt_vec_or_original(&data, version);
        assert!(!succ);
        assert!(!store);

        println!("test speed");
        let test_speed = |len: usize, name: &str| {
            let mut data: Vec<u8> = vec![];
            let mut rng = thread_rng();
            for _ in 0..len {
                data.push(rng.gen_range(0..255));
            }
            let start: Instant = Instant::now();
            let encrypted = encrypt_vec_or_original(&data, version, len);
            assert_ne!(data, decrypted);
            let t1 = start.elapsed();
            let start = Instant::now();
            let (decrypted, _, _) = decrypt_vec_or_original(&encrypted, version);
            let t2 = start.elapsed();
            assert_eq!(data, decrypted);
            println!("{name}");
            println!("encrypt:{:?}, decrypt:{:?}", t1, t2);

            let start: Instant = Instant::now();
            let encrypted = base64::encode(&data, base64::Variant::Original);
            let t1 = start.elapsed();
            let start = Instant::now();
            let decrypted = base64::decode(&encrypted, base64::Variant::Original).unwrap();
            let t2 = start.elapsed();
            assert_eq!(data, decrypted);
            println!("base64, encrypt:{:?}, decrypt:{:?}", t1, t2,);
        };
        test_speed(128, "128");
        test_speed(1024, "1k");
        test_speed(1024 * 1024, "1M");
        test_speed(10 * 1024 * 1024, "10M");
        test_speed(100 * 1024 * 1024, "100M");
    }

    #[test]
    fn test_temporary_password_rotation_interval() {
        use super::*;

        let generated_at = Instant::now();
        assert!(!temporary_password_rotation_due(
            generated_at,
            generated_at + TEMPORARY_PASSWORD_ROTATION_INTERVAL - Duration::from_secs(1)
        ));
        assert!(temporary_password_rotation_due(
            generated_at,
            generated_at + TEMPORARY_PASSWORD_ROTATION_INTERVAL
        ));
        assert!(temporary_password_rotation_due(
            generated_at,
            generated_at + TEMPORARY_PASSWORD_ROTATION_INTERVAL + Duration::from_secs(1)
        ));
        assert!(!temporary_password_rotation_due(
            generated_at,
            generated_at - Duration::from_secs(1)
        ));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_temporary_password_gui_lease_follows_connection_lifetime() {
        use super::*;

        TEMPORARY_PASSWORD_GUI_CONNECTIONS.store(0, Ordering::SeqCst);
        assert!(!temporary_password_available_for_auth());
        let first = acquire_temporary_password_gui_lease();
        assert!(temporary_password_available_for_auth());
        let second = acquire_temporary_password_gui_lease();
        drop(first);
        assert!(temporary_password_available_for_auth());
        drop(second);
        assert!(!temporary_password_available_for_auth());
    }

    #[test]
    fn test_is_encrypted() {
        use super::*;
        use sodiumoxide::base64::{encode, Variant};
        use sodiumoxide::crypto::secretbox;

        // Empty data should not be considered encrypted
        assert!(!is_encrypted(b""));
        assert!(!is_encrypted(b"0"));
        assert!(!is_encrypted(b"00"));

        // Data without "00" prefix should not be considered encrypted
        assert!(!is_encrypted(b"01abcd"));
        assert!(!is_encrypted(b"99abcd"));
        assert!(!is_encrypted(b"hello world"));

        // Data with "00" prefix but invalid base64 should not be considered encrypted
        assert!(!is_encrypted(b"00!!!invalid base64!!!"));
        assert!(!is_encrypted(b"00@#$%"));

        // Data with "00" prefix and valid base64 but shorter than MACBYTES is not encrypted
        assert!(!is_encrypted(b"00YWJjZA==")); // "abcd" in base64
        assert!(!is_encrypted(b"00SGVsbG8gV29ybGQ=")); // "Hello World" in base64

        // Data with "00" prefix and valid base64 with decoded len == MACBYTES is considered encrypted
        let exact_mac = vec![0u8; secretbox::MACBYTES];
        let exact_mac_b64 = encode(&exact_mac, Variant::Original);
        let exact_mac_candidate = format!("00{exact_mac_b64}");
        assert!(is_encrypted(exact_mac_candidate.as_bytes()));

        // Real encrypted data should be detected
        let version = "00";
        let max_len = 128;
        let encrypted_str = encrypt_str_or_original("1", version, max_len);
        assert!(is_encrypted(encrypted_str.as_bytes()));
        let encrypted_vec = encrypt_vec_or_original(b"1", version, max_len);
        assert!(is_encrypted(&encrypted_vec));

        // Original unencrypted data should not be detected as encrypted
        assert!(!is_encrypted(b"1"));
        assert!(!is_encrypted("1".as_bytes()));
    }

    #[test]
    fn test_encrypted_payload_min_len_macbytes() {
        use super::*;
        use sodiumoxide::base64::{decode, Variant};
        use sodiumoxide::crypto::secretbox;

        let version = "00";
        let max_len = 128;

        let encrypted_str = encrypt_str_or_original("1", version, max_len);
        let decoded = decode(&encrypted_str.as_bytes()[VERSION_LEN..], Variant::Original).unwrap();
        assert!(
            decoded.len() >= secretbox::MACBYTES,
            "decoded encrypted payload must be at least MACBYTES"
        );

        let encrypted_vec = encrypt_vec_or_original(b"1", version, max_len);
        let decoded = decode(&encrypted_vec[VERSION_LEN..], Variant::Original).unwrap();
        assert!(
            decoded.len() >= secretbox::MACBYTES,
            "decoded encrypted payload must be at least MACBYTES"
        );
    }

    #[test]
    fn test_encryption_uses_random_nonce() {
        use super::*;

        let data = b"test password 123";
        let encrypted1 = symmetric_crypt(data, true).unwrap();
        let encrypted2 = symmetric_crypt(data, true).unwrap();

        assert_eq!(encrypted1.first(), Some(&FORMAT_V1));
        assert_eq!(encrypted2.first(), Some(&FORMAT_V1));
        assert_eq!(
            encrypted1.len(),
            1 + secretbox::NONCEBYTES + data.len() + secretbox::MACBYTES
        );
        assert_ne!(encrypted1, encrypted2);
        assert_eq!(symmetric_crypt(&encrypted1, false).unwrap(), data);
        assert_eq!(symmetric_crypt(&encrypted2, false).unwrap(), data);
    }

    #[test]
    fn test_decrypt_legacy_zero_nonce_payload() {
        use super::*;
        use std::convert::TryInto;

        let data = b"test password 123";
        let uuid = crate::get_uuid();
        let mut keybuf = uuid.clone();
        keybuf.resize(secretbox::KEYBYTES, 0);
        let key = secretbox::Key(keybuf.try_into().unwrap());
        let nonce = secretbox::Nonce([0; secretbox::NONCEBYTES]);
        let encrypted = secretbox::seal(data, &nonce, &key);

        assert_eq!(symmetric_crypt(&encrypted, false).unwrap(), data);
    }

    #[test]
    fn test_decrypt_legacy_payload_starting_with_v1_marker() {
        use super::*;
        use std::convert::TryInto;

        let mut keybuf = crate::get_uuid();
        keybuf.resize(secretbox::KEYBYTES, 0);
        let key = secretbox::Key(keybuf.try_into().unwrap());
        let nonce = secretbox::Nonce([0; secretbox::NONCEBYTES]);

        for i in 0..=u16::MAX {
            let data = format!("legacy collision payload {i:05}");
            let encrypted = secretbox::seal(data.as_bytes(), &nonce, &key);
            if encrypted.first() == Some(&FORMAT_V1) {
                assert_eq!(symmetric_crypt(&encrypted, false).unwrap(), data.as_bytes());
                return;
            }
        }

        panic!("failed to find legacy payload starting with FORMAT_V1");
    }

    #[test]
    fn test_invalid_short_v1_payload_returns_error() {
        use super::*;

        let encrypted = vec![FORMAT_V1];

        assert!(symmetric_crypt(&encrypted, false).is_err());
    }

    #[test]
    fn test_decrypt_legacy_string_does_not_request_store() {
        use super::*;
        use sodiumoxide::base64::{encode, Variant};
        use std::convert::TryInto;

        let data = "test password 123";
        let uuid = crate::get_uuid();
        let mut keybuf = uuid.clone();
        keybuf.resize(secretbox::KEYBYTES, 0);
        let key = secretbox::Key(keybuf.try_into().unwrap());
        let nonce = secretbox::Nonce([0; secretbox::NONCEBYTES]);
        let encrypted = secretbox::seal(data.as_bytes(), &nonce, &key);
        let encrypted = "00".to_owned() + &encode(encrypted, Variant::Original);

        let (decrypted, success, store) = decrypt_str_or_original(&encrypted, "00");

        assert_eq!(decrypted, data);
        assert!(success);
        assert!(!store);
    }

    #[test]
    fn test_decrypt_legacy_vec_does_not_request_store() {
        use super::*;
        use sodiumoxide::base64::{encode, Variant};
        use std::convert::TryInto;

        let data = b"test password 123";
        let uuid = crate::get_uuid();
        let mut keybuf = uuid.clone();
        keybuf.resize(secretbox::KEYBYTES, 0);
        let key = secretbox::Key(keybuf.try_into().unwrap());
        let nonce = secretbox::Nonce([0; secretbox::NONCEBYTES]);
        let encrypted = secretbox::seal(data, &nonce, &key);
        let encrypted = ("00".to_owned() + &encode(encrypted, Variant::Original)).into_bytes();

        let (decrypted, success, store) = decrypt_vec_or_original(&encrypted, "00");

        assert_eq!(decrypted, data);
        assert!(success);
        assert!(!store);
    }

    // Test decryption fallback when data was encrypted with key_pair but decryption tries machine_uid first
    #[test]
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    fn test_decrypt_with_pk_fallback() {
        use sodiumoxide::crypto::secretbox;
        use std::convert::TryInto;

        let uuid = crate::get_uuid();
        let pk = crate::config::Config::get_key_pair().1;

        // Ensure uuid != pk, otherwise fallback branch won't be tested
        if uuid == pk {
            eprintln!("skip: uuid == pk, fallback branch won't be tested");
            return;
        }

        let data = b"test password 123";
        let nonce = secretbox::Nonce([0; secretbox::NONCEBYTES]);

        // Encrypt with pk (simulating machine_uid failure during encryption)
        let mut pk_keybuf = pk;
        pk_keybuf.resize(secretbox::KEYBYTES, 0);
        let pk_key = secretbox::Key(pk_keybuf.try_into().unwrap());
        let encrypted = secretbox::seal(data, &nonce, &pk_key);

        // Decrypt using symmetric_crypt (should fallback to pk since uuid differs)
        let decrypted = super::symmetric_crypt(&encrypted, false);
        assert!(
            decrypted.is_ok(),
            "Decryption with pk fallback should succeed"
        );
        assert_eq!(decrypted.unwrap(), data);
    }

    #[test]
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    fn test_decrypt_v1_with_pk_fallback() {
        use super::*;
        use sodiumoxide::base64::{encode, Variant};
        use sodiumoxide::crypto::secretbox;
        use std::convert::TryInto;

        let uuid = crate::get_uuid();
        let pk = crate::config::Config::get_key_pair().1;

        if uuid == pk {
            eprintln!("skip: uuid == pk, fallback branch won't be tested");
            return;
        }

        let data = b"test password 123";
        let nonce = secretbox::gen_nonce();

        let mut pk_keybuf = pk;
        pk_keybuf.resize(secretbox::KEYBYTES, 0);
        let pk_key = secretbox::Key(pk_keybuf.try_into().unwrap());
        let ciphertext = secretbox::seal(data, &nonce, &pk_key);

        let mut encrypted = Vec::with_capacity(1 + secretbox::NONCEBYTES + ciphertext.len());
        encrypted.push(FORMAT_V1);
        encrypted.extend(nonce.0);
        encrypted.extend(ciphertext);

        assert_eq!(super::symmetric_crypt(&encrypted, false).unwrap(), data);

        let encrypted_str = "00".to_owned() + &encode(&encrypted, Variant::Original);
        let (decrypted, success, store) = decrypt_str_or_original(&encrypted_str, "00");
        assert_eq!(decrypted.as_bytes(), data);
        assert!(success);
        assert!(!store);

        let encrypted_vec = encrypted_str.into_bytes();
        let (decrypted, success, store) = decrypt_vec_or_original(&encrypted_vec, "00");
        assert_eq!(decrypted, data);
        assert!(success);
        assert!(!store);
    }

    #[test]
    fn test_local_secret_round_trip_and_legacy_migration() {
        use super::*;

        let encrypted = encrypt_local_secret_str("SavedPeer1!", 128).unwrap();
        assert!(encrypted.starts_with(LOCAL_SECRET_ENC_VERSION));
        assert!(is_local_secret_encrypted(encrypted.as_bytes()));
        let (plaintext, decrypted, should_migrate) = decrypt_local_secret_str(&encrypted);
        assert_eq!(plaintext, "SavedPeer1!");
        assert!(decrypted);
        assert!(!should_migrate);

        let legacy = encrypt_str_or_original("SavedPeer1!", "00", 128);
        let (plaintext, decrypted, should_migrate) = decrypt_local_secret_str(&legacy);
        assert_eq!(plaintext, "SavedPeer1!");
        assert!(decrypted);
        assert!(should_migrate);

        let invalid_current = format!("{}not-valid-base64", LOCAL_SECRET_ENC_VERSION);
        let (plaintext, decrypted, should_migrate) = decrypt_local_secret_str(&invalid_current);
        assert!(plaintext.is_empty());
        assert!(!decrypted);
        assert!(!should_migrate);

        // Plaintext that merely resembles the storage prefix must still be
        // encrypted instead of being written through unchanged.
        let prefix_shaped_plaintext = format!(
            "{}{}",
            LOCAL_SECRET_ENC_VERSION,
            base64::encode(
                [7u8; LOCAL_SECRET_MIN_ENCODED_BYTES],
                base64::Variant::Original
            )
        );
        let encrypted = encrypt_local_secret_str(&prefix_shaped_plaintext, 128).unwrap();
        assert_ne!(encrypted, prefix_shaped_plaintext);
        assert_eq!(
            decrypt_local_secret_str(&encrypted).0,
            prefix_shaped_plaintext
        );

        let legacy_local_ciphertext = legacy_local_secret_crypt(b"SavedPeer1!", true).unwrap();
        let legacy_local = LEGACY_LOCAL_SECRET_ENC_VERSION.to_owned()
            + &base64::encode(legacy_local_ciphertext, base64::Variant::Original);
        assert!(is_local_secret_encrypted(legacy_local.as_bytes()));
        let (plaintext, decrypted, should_migrate) = decrypt_local_secret_str(&legacy_local);
        assert_eq!(plaintext, "SavedPeer1!");
        assert!(decrypted);
        assert!(should_migrate);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_local_secret_dpapi_requires_matching_machine_entropy() {
        use super::*;

        let encrypted =
            local_secret_crypt_with_entropy(b"machine-bound", b"machine-a", true).unwrap();
        assert_eq!(
            local_secret_crypt_with_entropy(&encrypted, b"machine-a", false).unwrap(),
            b"machine-bound"
        );
        assert!(local_secret_crypt_with_entropy(&encrypted, b"machine-b", false).is_err());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_parse_raw_smbios_system_uuid() {
        use super::*;

        let expected = [
            0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef,
        ];
        let mut table = vec![1, 24, 1, 0, 1, 2, 3, 4];
        table.extend(expected);
        table.extend([0, 0]);
        table.extend([127, 4, 0, 0, 0, 0]);
        let mut raw = vec![0, 3, 2, 0];
        raw.extend((table.len() as u32).to_le_bytes());
        raw.extend(table);
        assert_eq!(parse_raw_smbios_system_uuid(&raw), Some(expected));

        raw[16..32].fill(0xff);
        assert_eq!(parse_raw_smbios_system_uuid(&raw), None);
        raw.truncate(raw.len() - 1);
        assert_eq!(parse_raw_smbios_system_uuid(&raw), None);
    }
}
