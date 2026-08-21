use crate::{
    protobuf::Message as _,
    rendezvous_proto::{DeviceLease, IdentityRotation, RelayAuth, RelayTicket},
    sodiumoxide::{crypto::sign, randombytes},
    ResultType,
};
use std::{
    convert::TryFrom,
    sync::OnceLock,
    time::{SystemTime, UNIX_EPOCH},
};

const DEVICE_LEASE_CONTEXT: &[u8] = b"masterdesk-device-lease-v1";
const IDENTITY_ROTATION_CONTEXT: &[u8] = b"masterdesk-identity-rotation-v1";
const RELAY_AUTH_CONTEXT: &[u8] = b"masterdesk-relay-auth-v1";
const RELAY_TICKET_CONTEXT: &[u8] = b"masterdesk-relay-ticket-v1";
static PROCESS_SESSION_NONCE: OnceLock<Vec<u8>> = OnceLock::new();

fn append_bytes(payload: &mut Vec<u8>, value: &[u8]) {
    let len = u32::try_from(value.len()).unwrap_or(u32::MAX);
    payload.extend_from_slice(&len.to_be_bytes());
    payload.extend_from_slice(value);
}

fn append_str(payload: &mut Vec<u8>, value: &str) {
    append_bytes(payload, value.as_bytes());
}

fn append_i64(payload: &mut Vec<u8>, value: i64) {
    payload.extend_from_slice(&value.to_be_bytes());
}

fn append_i32(payload: &mut Vec<u8>, value: i32) {
    payload.extend_from_slice(&value.to_be_bytes());
}

pub fn unix_timestamp_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| i64::try_from(duration.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or_default()
}

pub fn timestamp_is_fresh(timestamp: i64, now: i64, allowed_skew_secs: u64) -> bool {
    timestamp.abs_diff(now) <= allowed_skew_secs
}

pub fn random_nonce(length: usize) -> Vec<u8> {
    randombytes::randombytes(length)
}

pub fn process_session_nonce() -> &'static [u8] {
    PROCESS_SESSION_NONCE
        .get_or_init(|| random_nonce(32))
        .as_slice()
}

/// Initializes this process with the nonce owned by the installed service.
///
/// MasterDesk is multi-process on Windows: the service can replace `--server`
/// during a console/RDP handoff, while one or more GUI processes keep running.
/// Those processes must use one runtime nonce or the server will correctly
/// interpret them as cloned installations. This remains fail-closed: once any
/// code has consumed a locally generated nonce it cannot be replaced.
pub fn initialize_process_session_nonce(session_nonce: Vec<u8>) -> bool {
    if session_nonce.len() < 16 {
        return false;
    }
    if let Some(current) = PROCESS_SESSION_NONCE.get() {
        return current == &session_nonce;
    }
    PROCESS_SESSION_NONCE.set(session_nonce).is_ok()
}

pub fn secret_key_from_bytes(value: &[u8]) -> Option<sign::SecretKey> {
    sign::SecretKey::from_slice(value)
}

pub fn public_key_from_bytes(value: &[u8]) -> Option<sign::PublicKey> {
    sign::PublicKey::from_slice(value)
}

pub fn public_key_from_base64(value: &str) -> Option<sign::PublicKey> {
    crate::base64::decode(value)
        .ok()
        .and_then(|bytes| public_key_from_bytes(&bytes))
}

fn sign_payload(payload: &[u8], secret_key: &sign::SecretKey) -> Vec<u8> {
    sign::sign_detached(payload, secret_key).as_ref().to_vec()
}

fn verify_payload(payload: &[u8], signature: &[u8], public_key: &sign::PublicKey) -> bool {
    let Ok(signature) = sign::Signature::from_bytes(signature) else {
        return false;
    };
    sign::verify_detached(&signature, payload, public_key)
}

pub fn device_lease_payload(
    id: &str,
    installation_id: &[u8],
    session_nonce: &[u8],
    timestamp: i64,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(
        DEVICE_LEASE_CONTEXT.len() + id.len() + installation_id.len() + session_nonce.len() + 32,
    );
    append_bytes(&mut payload, DEVICE_LEASE_CONTEXT);
    append_str(&mut payload, id);
    append_bytes(&mut payload, installation_id);
    append_bytes(&mut payload, session_nonce);
    append_i64(&mut payload, timestamp);
    payload
}

pub fn new_device_lease(
    id: &str,
    installation_id: &[u8],
    session_nonce: &[u8],
    secret_key: &sign::SecretKey,
) -> DeviceLease {
    let timestamp = unix_timestamp_secs();
    let payload = device_lease_payload(id, installation_id, session_nonce, timestamp);
    DeviceLease {
        installation_id: installation_id.to_vec().into(),
        session_nonce: session_nonce.to_vec().into(),
        timestamp,
        signature: sign_payload(&payload, secret_key).into(),
        ..Default::default()
    }
}

pub fn verify_device_lease(id: &str, lease: &DeviceLease, public_key: &sign::PublicKey) -> bool {
    let payload = device_lease_payload(
        id,
        &lease.installation_id,
        &lease.session_nonce,
        lease.timestamp,
    );
    verify_payload(&payload, &lease.signature, public_key)
}

pub fn identity_rotation_payload(
    id: &str,
    session_nonce: &[u8],
    issued_at: i64,
    nonce: &[u8],
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(
        IDENTITY_ROTATION_CONTEXT.len() + id.len() + session_nonce.len() + nonce.len() + 32,
    );
    append_bytes(&mut payload, IDENTITY_ROTATION_CONTEXT);
    append_str(&mut payload, id);
    append_bytes(&mut payload, session_nonce);
    append_i64(&mut payload, issued_at);
    append_bytes(&mut payload, nonce);
    payload
}

pub fn new_identity_rotation(
    id: &str,
    session_nonce: &[u8],
    secret_key: &sign::SecretKey,
) -> IdentityRotation {
    let issued_at = unix_timestamp_secs();
    let nonce = random_nonce(24);
    let payload = identity_rotation_payload(id, session_nonce, issued_at, &nonce);
    IdentityRotation {
        session_nonce: session_nonce.to_vec().into(),
        issued_at,
        nonce: nonce.into(),
        signature: sign_payload(&payload, secret_key).into(),
        ..Default::default()
    }
}

pub fn verify_identity_rotation(
    id: &str,
    rotation: &IdentityRotation,
    public_key: &sign::PublicKey,
) -> bool {
    let payload = identity_rotation_payload(
        id,
        &rotation.session_nonce,
        rotation.issued_at,
        &rotation.nonce,
    );
    verify_payload(&payload, &rotation.signature, public_key)
}

pub fn relay_auth_payload(
    target_id: &str,
    uuid: &str,
    relay_server: &str,
    conn_type: i32,
    requester_id: &str,
    session_nonce: &[u8],
    timestamp: i64,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(
        RELAY_AUTH_CONTEXT.len()
            + target_id.len()
            + uuid.len()
            + relay_server.len()
            + requester_id.len()
            + session_nonce.len()
            + 40,
    );
    append_bytes(&mut payload, RELAY_AUTH_CONTEXT);
    append_str(&mut payload, target_id);
    append_str(&mut payload, uuid);
    append_str(&mut payload, relay_server);
    append_i32(&mut payload, conn_type);
    append_str(&mut payload, requester_id);
    append_bytes(&mut payload, session_nonce);
    append_i64(&mut payload, timestamp);
    payload
}

pub fn new_relay_auth(
    target_id: &str,
    uuid: &str,
    relay_server: &str,
    conn_type: i32,
    requester_id: &str,
    session_nonce: &[u8],
    secret_key: &sign::SecretKey,
) -> RelayAuth {
    let timestamp = unix_timestamp_secs();
    let payload = relay_auth_payload(
        target_id,
        uuid,
        relay_server,
        conn_type,
        requester_id,
        session_nonce,
        timestamp,
    );
    RelayAuth {
        requester_id: requester_id.to_owned(),
        session_nonce: session_nonce.to_vec().into(),
        timestamp,
        signature: sign_payload(&payload, secret_key).into(),
        ..Default::default()
    }
}

pub fn verify_relay_auth(
    target_id: &str,
    uuid: &str,
    relay_server: &str,
    conn_type: i32,
    auth: &RelayAuth,
    public_key: &sign::PublicKey,
) -> bool {
    let payload = relay_auth_payload(
        target_id,
        uuid,
        relay_server,
        conn_type,
        &auth.requester_id,
        &auth.session_nonce,
        auth.timestamp,
    );
    verify_payload(&payload, &auth.signature, public_key)
}

pub fn relay_ticket_payload(ticket: &RelayTicket) -> ResultType<Vec<u8>> {
    let mut unsigned = ticket.clone();
    unsigned.signature.clear();
    let encoded = unsigned.write_to_bytes()?;
    let mut payload = Vec::with_capacity(RELAY_TICKET_CONTEXT.len() + encoded.len() + 4);
    append_bytes(&mut payload, RELAY_TICKET_CONTEXT);
    append_bytes(&mut payload, &encoded);
    Ok(payload)
}

pub fn sign_relay_ticket(ticket: &mut RelayTicket, secret_key: &sign::SecretKey) -> ResultType<()> {
    let payload = relay_ticket_payload(ticket)?;
    ticket.signature = sign_payload(&payload, secret_key).into();
    Ok(())
}

pub fn verify_relay_ticket(ticket: &RelayTicket, public_key: &sign::PublicKey) -> bool {
    relay_ticket_payload(ticket)
        .map(|payload| verify_payload(&payload, &ticket.signature, public_key))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rendezvous_proto::ConnType;

    #[test]
    fn signed_device_messages_round_trip_and_are_bound_to_the_session() {
        let (public_key, secret_key) = sign::gen_keypair();
        let lease = new_device_lease("123456789", b"installation", b"session-a", &secret_key);
        assert!(verify_device_lease("123456789", &lease, &public_key));
        assert!(!verify_device_lease("987654321", &lease, &public_key));

        let rotation = new_identity_rotation("123456789", b"session-a", &secret_key);
        assert!(verify_identity_rotation(
            "123456789",
            &rotation,
            &public_key
        ));
        assert_ne!(&rotation.session_nonce[..], b"session-b");
    }

    #[test]
    fn relay_auth_and_ticket_reject_modified_fields() {
        let (public_key, secret_key) = sign::gen_keypair();
        let auth = new_relay_auth(
            "target",
            "uuid",
            "relay.example",
            ConnType::DEFAULT_CONN as i32,
            "controller",
            b"session",
            &secret_key,
        );
        assert!(verify_relay_auth(
            "target",
            "uuid",
            "relay.example",
            ConnType::DEFAULT_CONN as i32,
            &auth,
            &public_key,
        ));
        assert!(!verify_relay_auth(
            "other-target",
            "uuid",
            "relay.example",
            ConnType::DEFAULT_CONN as i32,
            &auth,
            &public_key,
        ));

        let now = unix_timestamp_secs();
        let mut ticket = RelayTicket {
            version: 1,
            key_id: "2026-08".to_owned(),
            ticket_id: "ticket".to_owned(),
            relay_session_id: "session".to_owned(),
            role: "controller".to_owned(),
            device_id: "controller".to_owned(),
            controller_id: "controller".to_owned(),
            controlled_id: "target".to_owned(),
            relay_server: "relay.example".to_owned(),
            issued_at: now,
            expires_at: now + 60,
            conn_type: ConnType::DEFAULT_CONN.into(),
            max_bytes: 1024,
            max_seconds: 60,
            ..Default::default()
        };
        sign_relay_ticket(&mut ticket, &secret_key).expect("ticket should be serializable");
        assert!(verify_relay_ticket(&ticket, &public_key));
        ticket.device_id = "attacker".to_owned();
        assert!(!verify_relay_ticket(&ticket, &public_key));
    }
}
