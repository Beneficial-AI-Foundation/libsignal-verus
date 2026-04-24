//
// Tests exhibiting the shared-state seams documented in shared_state_seams.md.
// These are intended as executable evidence that each finding is mechanically
// reproducible at the Rust protocol boundary, not as regression guards.
//

mod support;

use std::time::SystemTime;

use futures_util::FutureExt;
use libsignal_protocol::*;
use rand::TryRngCore as _;
use rand::rngs::OsRng;
#[allow(unused_imports)]
use support::*;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Seam 2: sealed_sender_decrypt_to_usmc does not cross-check the sender
// certificate's identity key against the receiver's IdentityKeyStore.
//
// The paper's attack #2, issue 1. Unpatched on the Rust side at upstream
// commit 0a58e80b. The full exploit chain requires Android's missing
// PLAINTEXT_CONTENT validation (issue 2, patched separately); this test
// isolates the Rust-side gadget.
// ---------------------------------------------------------------------------

#[test]
fn seam2_sss_accepts_cert_key_not_in_identity_store() -> Result<(), SignalProtocolError> {
    async {
        let mut rng = OsRng.unwrap_err();

        // --- Alice has a real, long-term identity key. Bob has recorded it.
        let alice_real = IdentityKeyPair::generate(&mut rng);
        let alice_uuid = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa".to_string();
        let alice_device = DeviceId::new(1).unwrap();
        let alice_addr = ProtocolAddress::new(alice_uuid.clone(), alice_device);

        let bob_keys = IdentityKeyPair::generate(&mut rng);
        let bob_uuid = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb".to_string();
        let bob_addr = ProtocolAddress::new(bob_uuid, DeviceId::new(1).unwrap());
        let mut bob_store = InMemSignalProtocolStore::new(bob_keys, 1)?;

        // Bob saves Alice's *real* identity (as if safety numbers were compared).
        bob_store
            .save_identity(&alice_addr, alice_real.identity_key())
            .await?;

        // --- Malicious server: forge a SenderCertificate naming Alice but
        // carrying a completely different identity key (attacker's).
        let attacker_keys = IdentityKeyPair::generate(&mut rng);
        let trust_root = KeyPair::generate(&mut rng);
        let server_key = KeyPair::generate(&mut rng);
        let server_cert =
            ServerCertificate::new(1, server_key.public_key, &trust_root.private_key, &mut rng)?;
        let expiration = Timestamp::from_epoch_millis(
            SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64
                + 3600 * 1000,
        );

        let forged_cert = SenderCertificate::new(
            alice_uuid.clone(),           // claims to be Alice
            None,
            *attacker_keys.public_key(),  // but with the attacker's key
            alice_device,
            expiration,
            server_cert,
            &server_key.private_key,
            &mut rng,
        )?;

        // --- Encrypt SSS using the attacker's store (so that the SSS x_DH runs
        // with the attacker's private key, matching the forged cert's pubkey).
        let mut attacker_store = InMemSignalProtocolStore::new(attacker_keys, 42)?;
        attacker_store
            .save_identity(&bob_addr, bob_store.get_identity_key_pair().await?.identity_key())
            .await?;

        let alice_usmc = UnidentifiedSenderMessageContent::new(
            CiphertextMessageType::Whisper,
            forged_cert,
            b"arbitrary payload that Bob should never accept from a forged cert".to_vec(),
            ContentHint::Default,
            None,
        )?;

        let ctext = sealed_sender_encrypt_from_usmc(
            &bob_addr,
            &alice_usmc,
            &attacker_store.identity_store,
            &mut rng,
        )
        .await?;

        // --- Bob decrypts at the SSS layer only.
        let decrypted =
            sealed_sender_decrypt_to_usmc(&ctext, &bob_store.identity_store).await?;

        // The SSS layer accepts the forged cert. The sender UUID reported is Alice's,
        // but the cert's key is the attacker's — different from what Bob trusts.
        assert_eq!(decrypted.sender()?.sender_uuid()?, alice_uuid.as_str());
        assert_eq!(
            decrypted.sender()?.key()?.serialize(),
            attacker_keys.public_key().serialize(),
        );
        assert_ne!(
            decrypted.sender()?.key()?.serialize(),
            alice_real.public_key().serialize(),
        );

        // Bob's identity store still holds alice_real — the SSS layer never consulted it.
        let bob_view_of_alice = bob_store.get_identity(&alice_addr).await?;
        assert_eq!(
            bob_view_of_alice.as_ref().map(|k| k.serialize()),
            Some(alice_real.identity_key().serialize()),
        );

        Ok(())
    }
    .now_or_never()
    .expect("sync")
}

// ---------------------------------------------------------------------------
// Seam 3: SenderCertificate::new / ::validate accept any UUID string,
// including PNI-prefixed strings. No ACI kind check anywhere in rust/protocol/.
// ---------------------------------------------------------------------------

#[test]
fn seam3_sender_certificate_accepts_pni_uuid() -> Result<(), SignalProtocolError> {
    let mut rng = OsRng.unwrap_err();

    let trust_root = KeyPair::generate(&mut rng);
    let server_key = KeyPair::generate(&mut rng);
    let server_cert =
        ServerCertificate::new(1, server_key.public_key, &trust_root.private_key, &mut rng)?;

    let some_identity = IdentityKeyPair::generate(&mut rng);
    let expiration = Timestamp::from_epoch_millis(
        SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
            + 3600 * 1000,
    );

    // "PNI:<uuid>" is Signal's conventional string form for a PNI-rooted
    // ProtocolAddress. libsignal stores sender_uuid as a raw String, so the
    // constructor accepts it verbatim.
    let pni_uuid = "PNI:12345678-aaaa-bbbb-cccc-123456789abc".to_string();

    let pni_cert = SenderCertificate::new(
        pni_uuid.clone(),
        None,
        *some_identity.public_key(),
        DeviceId::new(1).unwrap(),
        expiration,
        server_cert,
        &server_key.private_key,
        &mut rng,
    )?;

    // Signature validates (server-issued, just like any other SenderCertificate).
    assert!(pni_cert.validate(&trust_root.public_key, Timestamp::from_epoch_millis(
        SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
    ))?);
    // The PNI string round-trips unchanged.
    assert_eq!(pni_cert.sender_uuid()?, pni_uuid.as_str());

    Ok(())
}

// ---------------------------------------------------------------------------
// Seam 4a: InMemIdentityKeyStore::is_trusted_identity returns true for any
// never-seen (address, key) pair, regardless of direction.
// ---------------------------------------------------------------------------

#[test]
fn seam4_inmem_tofu_on_first_use() -> Result<(), SignalProtocolError> {
    async {
        let mut rng = OsRng.unwrap_err();
        let me = IdentityKeyPair::generate(&mut rng);
        let store = InMemIdentityKeyStore::new(me, 42);

        let attacker = IdentityKeyPair::generate(&mut rng);
        let any_addr = ProtocolAddress::new(
            "never-seen-uuid".to_string(),
            DeviceId::new(1).unwrap(),
        );

        for dir in [Direction::Sending, Direction::Receiving] {
            let dir_label = format!("{:?}", dir);
            let trusted = store
                .is_trusted_identity(&any_addr, attacker.identity_key(), dir)
                .await?;
            assert!(
                trusted,
                "first-use TOFU: attacker key accepted with no prior knowledge (direction={})",
                dir_label
            );
        }
        Ok(())
    }
    .now_or_never()
    .expect("sync")
}

// ---------------------------------------------------------------------------
// Seam 4b: after save_identity, is_trusted_identity returns the same value
// for Sending and Receiving — direction is ignored.
// ---------------------------------------------------------------------------

#[test]
fn seam4_inmem_ignores_direction() -> Result<(), SignalProtocolError> {
    async {
        let mut rng = OsRng.unwrap_err();
        let me = IdentityKeyPair::generate(&mut rng);
        let mut store = InMemIdentityKeyStore::new(me, 42);

        let peer = IdentityKeyPair::generate(&mut rng);
        let different_key = IdentityKeyPair::generate(&mut rng);
        let peer_addr = ProtocolAddress::new("peer".to_string(), DeviceId::new(1).unwrap());

        // Bind peer_addr to peer's real key.
        store
            .save_identity(&peer_addr, peer.identity_key())
            .await?;

        let send = store
            .is_trusted_identity(
                &peer_addr,
                different_key.identity_key(),
                Direction::Sending,
            )
            .await?;
        let recv = store
            .is_trusted_identity(
                &peer_addr,
                different_key.identity_key(),
                Direction::Receiving,
            )
            .await?;
        assert_eq!(send, recv, "direction must affect trust policy but does not");
        assert!(!send, "different key should not be trusted after save_identity");

        Ok(())
    }
    .now_or_never()
    .expect("sync")
}

// ---------------------------------------------------------------------------
// Seam 7: SKDM sender-label misbinding.
//
// process_sender_key_distribution_message stores sender-key state under the
// caller-provided ProtocolAddress. If the app labels the sender incorrectly
// when ingesting SKDM, future group_decrypt decisions are made relative to the
// wrong label.
// ---------------------------------------------------------------------------

#[test]
fn seam7_skdm_misbinding_allows_wrong_sender_label() -> Result<(), SignalProtocolError> {
    async {
        let mut csprng = OsRng.unwrap_err();
        let distribution_id = Uuid::from_u128(0xd1d1d1d1_7000_11eb_b32a_33b8a8a487a6);

        let alice_addr =
            ProtocolAddress::new("alice-aci-1111".to_string(), DeviceId::new(1).unwrap());
        let mallory_addr =
            ProtocolAddress::new("mallory-aci-2222".to_string(), DeviceId::new(1).unwrap());

        let mut alice_store = test_in_memory_protocol_store()?;
        let mut bob_store = test_in_memory_protocol_store()?;

        let sent_distribution_message = create_sender_key_distribution_message(
            &alice_addr,
            distribution_id,
            &mut alice_store,
            &mut csprng,
        )
        .await?;
        let recv_distribution_message =
            SenderKeyDistributionMessage::try_from(sent_distribution_message.serialized())?;

        // Misbinding: app incorrectly attributes Alice's SKDM to Mallory.
        process_sender_key_distribution_message(
            &mallory_addr,
            &recv_distribution_message,
            &mut bob_store,
        )
        .await?;

        let alice_ciphertext = group_encrypt(
            &mut alice_store,
            &alice_addr,
            distribution_id,
            b"group payload from alice",
            &mut csprng,
        )
        .await?;

        // Decrypt succeeds with the wrong (mislabeled) sender.
        let wrong_label_plaintext =
            group_decrypt(alice_ciphertext.serialized(), &mut bob_store, &mallory_addr).await?;
        assert_eq!(wrong_label_plaintext, b"group payload from alice");

        // Decrypt fails with the true sender label, since state was stored under Mallory.
        let true_label_result =
            group_decrypt(alice_ciphertext.serialized(), &mut bob_store, &alice_addr).await;
        assert!(
            matches!(
                true_label_result,
                Err(SignalProtocolError::NoSenderKeyState { .. })
            ),
            "expected NoSenderKeyState for the true sender label, got: {true_label_result:?}"
        );

        Ok(())
    }
    .now_or_never()
    .expect("sync")
}

// ---------------------------------------------------------------------------
// Seam 8: decrypt_to_usmc does not perform trust-root/timestamp validation.
//
// This API intentionally returns USMC before trust-root policy is applied.
// If apps consume sender metadata from this return value as "trusted sender"
// without explicit certificate validation, they can be misled.
// ---------------------------------------------------------------------------

#[test]
fn seam8_decrypt_to_usmc_accepts_sender_cert_without_trust_root_validation(
) -> Result<(), SignalProtocolError> {
    async {
        let mut rng = OsRng.unwrap_err();

        let sender_keys = IdentityKeyPair::generate(&mut rng);
        let sender_uuid = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa".to_string();
        let sender_device = DeviceId::new(1).unwrap();

        let receiver_keys = IdentityKeyPair::generate(&mut rng);
        let receiver_addr = ProtocolAddress::new(
            "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb".to_string(),
            DeviceId::new(1).unwrap(),
        );
        let mut receiver_store = InMemSignalProtocolStore::new(receiver_keys, 7)?;

        // Sender must know receiver's identity for sealed_sender_encrypt_from_usmc.
        receiver_store
            .save_identity(
                &ProtocolAddress::new(sender_uuid.clone(), sender_device),
                sender_keys.identity_key(),
            )
            .await?;
        let mut sender_store = InMemSignalProtocolStore::new(sender_keys, 9)?;
        sender_store
            .save_identity(
                &receiver_addr,
                receiver_store.get_identity_key_pair().await?.identity_key(),
            )
            .await?;

        // Build a sender certificate signed by an arbitrary root that the receiver
        // is not configured to trust.
        let untrusted_root = KeyPair::generate(&mut rng);
        let untrusted_server = KeyPair::generate(&mut rng);
        let server_cert = ServerCertificate::new(
            1,
            untrusted_server.public_key,
            &untrusted_root.private_key,
            &mut rng,
        )?;
        let expiration = Timestamp::from_epoch_millis(
            SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time went backwards")
                .as_millis() as u64
                + 3600 * 1000,
        );
        let sender_cert = SenderCertificate::new(
            sender_uuid.clone(),
            None,
            *sender_store.get_identity_key_pair().await?.public_key(),
            sender_device,
            expiration,
            server_cert,
            &untrusted_server.private_key,
            &mut rng,
        )?;

        let usmc = UnidentifiedSenderMessageContent::new(
            CiphertextMessageType::Whisper,
            sender_cert,
            b"opaque payload".to_vec(),
            ContentHint::Default,
            None,
        )?;
        let ctext = sealed_sender_encrypt_from_usmc(
            &receiver_addr,
            &usmc,
            &sender_store.identity_store,
            &mut rng,
        )
        .await?;

        let decrypted =
            sealed_sender_decrypt_to_usmc(&ctext, &receiver_store.identity_store).await?;

        // decrypt_to_usmc accepts and returns sender metadata.
        assert_eq!(decrypted.sender()?.sender_uuid()?, sender_uuid.as_str());

        // But trust-root validation remains caller responsibility.
        let unrelated_root = KeyPair::generate(&mut rng);
        assert!(
            !decrypted
                .sender()?
                .validate(&unrelated_root.public_key, expiration.sub_millis(1))?,
            "sender certificate should fail validation against an unrelated trust root"
        );

        Ok(())
    }
    .now_or_never()
    .expect("sync")
}
