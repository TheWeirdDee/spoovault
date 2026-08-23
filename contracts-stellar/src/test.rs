use super::*;
use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contracterror, contractimpl,
    crypto::Hash,
    testutils::Address as _,
    vec, Address, Env, IntoVal, String, Symbol, Val, Vec,
};

/// Minimal custom account contract standing in for a Soroban account
/// abstraction signer (e.g. a multisig or policy-gated wallet). Its
/// `__check_auth` is a real entry point invoked by the Soroban authorization
/// framework - exercising it (instead of relying on `mock_all_auths`) proves
/// that guardians can be custom account contracts, not just raw keypairs.
#[contract]
pub struct MockAaAccount;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum MockAaError {
    BadSignature = 1,
}

#[contractimpl]
impl CustomAccountInterface for MockAaAccount {
    type Signature = Val;
    type Error = MockAaError;

    fn __check_auth(
        _env: Env,
        _signature_payload: Hash<32>,
        _signature: Val,
        _auth_contexts: Vec<Context>,
    ) -> Result<(), MockAaError> {
        Ok(())
    }
}

/// Minimal registry contract used to verify the vault's deep,
/// `authorize_as_current_contract`-authorized cross-contract call on
/// document access grants.
#[contract]
pub struct MockAccessRegistry;

#[contractimpl]
impl MockAccessRegistry {
    pub fn record_grant(env: Env, document_id: u64, requester: Address) {
        env.storage()
            .instance()
            .set(&Symbol::new(&env, "last_grant"), &(document_id, requester));
    }
}

#[test]
fn test_register_and_get_public_key() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SpooVaultStellar);
    let client = SpooVaultStellarClient::new(&env, &contract_id);

    let user = Address::generate(&env);
    env.mock_all_auths();

    let pubkey = String::from_str(&env, "B64_STELLAR_PUBKEY_TEST");
    client.register_public_key(&user, &pubkey);

    let fetched = client.get_public_key(&user);
    assert_eq!(fetched, Some(pubkey));
}

#[test]
fn test_cross_chain_identity_registration_and_resolution() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SpooVaultStellar);
    let client = SpooVaultStellarClient::new(&env, &contract_id);

    let stellar_user = Address::generate(&env);
    env.mock_all_auths();

    let evm_address = String::from_str(&env, "0x64128680775Ef626379DeF6E5c815AeA8F4707Ef");
    let enc_pubkey = String::from_str(&env, "0x04bfcab5516089d846985a12");

    // Register cross-chain identity with public key
    client.register_cross_chain_identity(&stellar_user, &evm_address, &Some(enc_pubkey.clone()));

    // Resolve EVM address to Stellar Address
    let resolved_stellar = client.resolve_evm_to_stellar(&evm_address);
    assert_eq!(resolved_stellar, Some(stellar_user.clone()));

    // Resolve Stellar Address to EVM address
    let resolved_evm = client.resolve_stellar_to_evm(&stellar_user);
    assert_eq!(resolved_evm, Some(evm_address.clone()));

    // Resolve EVM address to Encryption Public Key
    let resolved_pubkey = client.resolve_evm_to_public_key(&evm_address);
    assert_eq!(resolved_pubkey, Some(enc_pubkey));

    // Resolve user's public key directly via Stellar Address
    let fetched_stellar_pubkey = client.get_public_key(&stellar_user);
    assert_eq!(fetched_stellar_pubkey, resolved_pubkey);
}

#[test]
fn test_cross_chain_identity_fallback_resolution() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SpooVaultStellar);
    let client = SpooVaultStellarClient::new(&env, &contract_id);

    let stellar_user = Address::generate(&env);
    env.mock_all_auths();

    let evm_address = String::from_str(&env, "0x1234567890123456789012345678901234567890");
    let stellar_pubkey = String::from_str(&env, "STELLAR_ENCRYPTION_PUBKEY_TEST");

    // Register stellar public key first
    client.register_public_key(&stellar_user, &stellar_pubkey);

    // Register cross-chain link without explicit separate pubkey
    client.register_cross_chain_identity(&stellar_user, &evm_address, &None);

    // Should resolve EVM address to the Stellar public key via fallback
    let resolved_pubkey = client.resolve_evm_to_public_key(&evm_address);
    assert_eq!(resolved_pubkey, Some(stellar_pubkey));
}

#[test]
fn test_create_vault_and_get_vault() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SpooVaultStellar);
    let client = SpooVaultStellarClient::new(&env, &contract_id);

    let creator = Address::generate(&env);
    let g1 = Address::generate(&env);
    let g2 = Address::generate(&env);
    env.mock_all_auths();

    let name = String::from_str(&env, "Soroban Vault");
    let desc = String::from_str(&env, "Stellar Soroban Secure Vault");
    let guardians = vec![&env, g1.clone(), g2.clone()];

    let vault_id = client.create_vault(&creator, &name, &desc, &guardians, &2);
    assert_eq!(vault_id, 1);

    let vault = client.get_vault(&vault_id).expect("Vault should exist");
    assert_eq!(vault.id, 1);
    assert_eq!(vault.creator, creator);
    assert_eq!(vault.approval_threshold, 2);
    assert!(vault.is_active);

    let invites_g1 = client.get_invites(&g1);
    assert_eq!(invites_g1.len(), 1);
    assert!(!invites_g1.get(0).unwrap().accepted);
}

#[test]
fn test_accept_guardian_invite() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SpooVaultStellar);
    let client = SpooVaultStellarClient::new(&env, &contract_id);

    let creator = Address::generate(&env);
    let g1 = Address::generate(&env);
    env.mock_all_auths();

    let name = String::from_str(&env, "Family Vault");
    let desc = String::from_str(&env, "Guardians Test");
    let guardians = vec![&env, g1.clone()];

    let vault_id = client.create_vault(&creator, &name, &desc, &guardians, &1);
    client.accept_guardian_invite(&g1, &vault_id);

    let vault = client.get_vault(&vault_id).unwrap();
    assert_eq!(vault.guardians.len(), 2);
    assert!(vault.guardians.contains(&g1));

    let invites = client.get_invites(&g1);
    assert!(invites.get(0).unwrap().accepted);
}

#[test]
fn test_add_document_and_access_flow() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SpooVaultStellar);
    let client = SpooVaultStellarClient::new(&env, &contract_id);

    let creator = Address::generate(&env);
    let g1 = Address::generate(&env);
    let requester = Address::generate(&env);
    env.mock_all_auths();

    let name = String::from_str(&env, "Financial Vault");
    let desc = String::from_str(&env, "Financial records");
    let guardians = vec![&env, g1.clone()];

    let vault_id = client.create_vault(&creator, &name, &desc, &guardians, &1);
    client.accept_guardian_invite(&g1, &vault_id);

    let meta = String::from_str(&env, "{\"title\":\"will.pdf\"}");
    let ipfs = String::from_str(&env, "QmTestIpfsHash");
    let guardians_list = vec![&env, creator.clone(), g1.clone()];
    let shares = vec![
        &env,
        String::from_str(&env, "share1"),
        String::from_str(&env, "share2"),
    ];

    let doc_id = client.add_document(
        &creator,
        &vault_id,
        &meta,
        &ipfs,
        &AccessLevel::Read,
        &ReleaseCondition::Anytime,
        &guardians_list,
        &shares,
    );
    assert_eq!(doc_id, 1);

    let doc = client.get_document(&doc_id).unwrap();
    assert_eq!(doc.ipfs_hash, ipfs);

    let req_id = client.request_access(&requester, &doc_id);
    assert_eq!(req_id, 1);

    let share_for_beneficiary = Some(String::from_str(&env, "bshare123"));
    client.approve_access(&creator, &req_id, &share_for_beneficiary);

    let req = client.get_access_request(&req_id).unwrap();
    assert_eq!(req.status, RequestStatus::Approved);
}

#[test]
fn test_ttl_extensions() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SpooVaultStellar);
    let client = SpooVaultStellarClient::new(&env, &contract_id);

    let creator = Address::generate(&env);
    let g1 = Address::generate(&env);
    let requester = Address::generate(&env);
    env.mock_all_auths();

    let name = String::from_str(&env, "TTL Vault");
    let desc = String::from_str(&env, "Testing TTL extensions");
    let guardians = vec![&env, g1.clone()];

    let vault_id = client.create_vault(&creator, &name, &desc, &guardians, &1);
    let doc_id = client.add_document(
        &creator,
        &vault_id,
        &String::from_str(&env, "meta"),
        &String::from_str(&env, "QmHash"),
        &AccessLevel::Read,
        &ReleaseCondition::Anytime,
        &vec![&env, creator.clone()],
        &vec![&env, String::from_str(&env, "share")],
    );
    let req_id = client.request_access(&requester, &doc_id);

    // Call explicit TTL extension endpoints
    client.extend_contract_ttl();
    client.extend_vault_ttl(&vault_id);
    client.extend_document_ttl(&doc_id);
    client.extend_request_ttl(&req_id);
}

#[test]
fn test_prove_life_and_emergency_mode() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SpooVaultStellar);
    let client = SpooVaultStellarClient::new(&env, &contract_id);

    let creator = Address::generate(&env);
    let g1 = Address::generate(&env);
    env.mock_all_auths();

    let name = String::from_str(&env, "Emergency Vault");
    let desc = String::from_str(&env, "Emergency release test");
    let guardians = vec![&env, g1.clone()];

    let vault_id = client.create_vault(&creator, &name, &desc, &guardians, &1);

    client.set_emergency_mode(&creator, &vault_id, &true);
    let state = client.get_release_state(&vault_id).unwrap();
    assert!(state.emergency_mode);

    client.prove_life(&creator, &vault_id);
    client.configure_vault_release(&creator, &vault_id, &(60 * 24 * 60 * 60));
    let updated_state = client.get_release_state(&vault_id).unwrap();
    assert_eq!(updated_state.inactivity_period, 60 * 24 * 60 * 60);
}

#[test]
fn test_contract_account_guardian_approves_via_custom_auth() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SpooVaultStellar);
    let client = SpooVaultStellarClient::new(&env, &contract_id);

    let creator = Address::generate(&env);
    // A deployed contract acting as a guardian - a custom account abstraction
    // signer, not a raw Stellar keypair.
    let aa_guardian = env.register_contract(None, MockAaAccount);
    let requester = Address::generate(&env);

    let name = String::from_str(&env, "AA Guardian Vault");
    let desc = String::from_str(&env, "Contract-account guardian test");
    let guardians = vec![&env, aa_guardian.clone()];

    env.mock_all_auths();
    let vault_id = client.create_vault(&creator, &name, &desc, &guardians, &1);

    // Contract addresses register as guardians the same way keypair
    // addresses do.
    client.accept_guardian_invite(&aa_guardian, &vault_id);
    let vault = client.get_vault(&vault_id).unwrap();
    assert!(vault.guardians.contains(&aa_guardian));

    let doc_id = client.add_document(
        &creator,
        &vault_id,
        &String::from_str(&env, "meta"),
        &String::from_str(&env, "QmHash"),
        &AccessLevel::Read,
        &ReleaseCondition::Anytime,
        &vec![&env, creator.clone()],
        &vec![&env, String::from_str(&env, "share")],
    );
    let req_id = client.request_access(&requester, &doc_id);

    // Drive the approval through the real Soroban auth framework (no
    // mock_all_auths) so the contract guardian's `__check_auth` is actually
    // invoked and must approve the call for `approve_access` to succeed.
    let args: Vec<Val> = (aa_guardian.clone(), req_id, None::<String>).into_val(&env);
    env.set_auths(&[soroban_sdk::testutils::MockAuth {
        address: &aa_guardian,
        invoke: &soroban_sdk::testutils::MockAuthInvoke {
            contract: &contract_id,
            fn_name: "approve_access",
            args,
            sub_invokes: &[],
        },
    }
    .into()]);

    client.approve_access(&aa_guardian, &req_id, &None);

    let req = client.get_access_request(&req_id).unwrap();
    assert_eq!(req.status, RequestStatus::Approved);
}

#[test]
fn test_deep_auth_invocation_notifies_access_registry() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SpooVaultStellar);
    let client = SpooVaultStellarClient::new(&env, &contract_id);
    let registry_addr = env.register_contract(None, MockAccessRegistry);

    let creator = Address::generate(&env);
    let g1 = Address::generate(&env);
    let requester = Address::generate(&env);
    env.mock_all_auths();

    let vault_id = client.create_vault(
        &creator,
        &String::from_str(&env, "Registry Vault"),
        &String::from_str(&env, "Deep auth invocation test"),
        &vec![&env, g1.clone()],
        &1,
    );
    client.set_access_registry(&creator, &vault_id, &registry_addr);
    client.accept_guardian_invite(&g1, &vault_id);

    let doc_id = client.add_document(
        &creator,
        &vault_id,
        &String::from_str(&env, "meta"),
        &String::from_str(&env, "QmHash"),
        &AccessLevel::Read,
        &ReleaseCondition::Anytime,
        &vec![&env, creator.clone()],
        &vec![&env, String::from_str(&env, "share")],
    );
    let req_id = client.request_access(&requester, &doc_id);

    // Approving fully grants access, which should trigger the vault's
    // `env.authorize_as_current_contract` sub-invocation calling the
    // registry's `record_grant` - a cross-contract call authorized by the
    // vault contract itself, not by the approving guardian.
    client.approve_access(&creator, &req_id, &None);

    let recorded: (u64, Address) = env.as_contract(&registry_addr, || {
        env.storage()
            .instance()
            .get(&Symbol::new(&env, "last_grant"))
            .unwrap()
    });
    assert_eq!(recorded, (doc_id, requester));
}

#[test]
fn test_guardian_revoke_access() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SpooVaultStellar);
    let client = SpooVaultStellarClient::new(&env, &contract_id);

    let creator = Address::generate(&env);
    let requester = Address::generate(&env);
    env.mock_all_auths();

    let vault_id = client.create_vault(
        &creator,
        &String::from_str(&env, "Revoke Vault"),
        &String::from_str(&env, "Guardian revoke test"),
        &vec![&env, Address::generate(&env)],
        &1,
    );
    let doc_id = client.add_document(
        &creator,
        &vault_id,
        &String::from_str(&env, "meta"),
        &String::from_str(&env, "QmHash"),
        &AccessLevel::Read,
        &ReleaseCondition::Anytime,
        &vec![&env, creator.clone()],
        &vec![&env, String::from_str(&env, "share")],
    );
    let req_id = client.request_access(&requester, &doc_id);
    client.approve_access(&creator, &req_id, &None);

    let req = client.get_access_request(&req_id).unwrap();
    assert_eq!(req.status, RequestStatus::Approved);

    client.revoke_access(&creator, &doc_id, &requester);

    // A fresh request is accepted again only because access was actually
    // cleared - `request_access` panics if `HasAccess` is still true.
    let req_id_2 = client.request_access(&requester, &doc_id);
    assert_ne!(req_id_2, req_id);
}

#[cfg(test)]
mod cross_chain_revocation {
    use super::*;
    use k256::ecdsa::signature::hazmat::PrehashSigner;
    use k256::ecdsa::SigningKey as EvmSigningKey;
    use soroban_sdk::xdr::ToXdr;

    struct EvmKeypair {
        signing_key: EvmSigningKey,
        address: BytesN<20>,
    }

    fn generate_evm_keypair(env: &Env, seed: u8) -> EvmKeypair {
        let signing_key = EvmSigningKey::from_bytes(&[seed; 32].into()).unwrap();
        let pk65: [u8; 65] = signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .try_into()
            .unwrap();
        // Ethereum address = keccak256(pubkey without the 0x04 prefix byte)[12..32].
        let pk_hash = env
            .crypto()
            .keccak256(&Bytes::from_array(env, &pk65).slice(1..65));
        let hash_bytes: Bytes = pk_hash.to_bytes().into();
        let address: BytesN<20> = hash_bytes.slice(12..32).try_into().unwrap();
        EvmKeypair { signing_key, address }
    }

    /// Builds the exact digest `recover_eth_address` verifies against (using
    /// the same `env.crypto()` host hash functions the contract itself
    /// uses, so there is no risk of a hand-rolled hash mismatching), then
    /// produces a real secp256k1 signature plus the recovery id that
    /// reproduces the signer's public key.
    #[allow(clippy::too_many_arguments)]
    fn sign_revocation(
        env: &Env,
        signer: &EvmSigningKey,
        vault_gid: &BytesN<32>,
        document_id: u64,
        target_evm_user: &BytesN<20>,
        target_stellar_user: &Address,
        nonce: u64,
    ) -> (BytesN<64>, u32) {
        let mut payload = Bytes::from_slice(env, b"RevokeAccess");
        payload.append(&Bytes::from(vault_gid.clone()));
        payload.append(&Bytes::from_array(env, &u256_be(document_id)));
        payload.append(&Bytes::from(target_evm_user.clone()));
        payload.append(&target_stellar_user.clone().to_xdr(env));
        payload.append(&Bytes::from_array(env, &u256_be(nonce)));
        let message_hash = env.crypto().keccak256(&payload);

        let mut prefixed = Bytes::from_slice(env, b"\x19Ethereum Signed Message:\n32");
        prefixed.append(&Bytes::from(message_hash.to_bytes()));
        let digest = env.crypto().keccak256(&prefixed);
        let digest_arr: [u8; 32] = digest.to_bytes().to_array();

        let sig: k256::ecdsa::Signature = signer.sign_prehash(&digest_arr).unwrap();
        let sig_arr: [u8; 64] = sig.to_bytes()[..].try_into().unwrap();
        let sig_bn = BytesN::from_array(env, &sig_arr);

        let expected_pk: [u8; 65] = signer
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .try_into()
            .unwrap();
        let mut recovery_id = 0u32;
        for rid in 0..4u32 {
            let recovered: [u8; 65] = env.crypto().secp256k1_recover(&digest, &sig_bn, rid).to_array();
            if recovered == expected_pk {
                recovery_id = rid;
                break;
            }
        }

        (sig_bn, recovery_id)
    }

    fn setup_linked_vault(env: &Env) -> (SpooVaultStellarClient<'static>, Address, u64, u64, EvmKeypair, BytesN<32>) {
        let contract_id = env.register_contract(None, SpooVaultStellar);
        let client = SpooVaultStellarClient::new(env, &contract_id);

        let creator = Address::generate(env);
        let requester = Address::generate(env);
        env.mock_all_auths();

        let vault_id = client.create_vault(
            &creator,
            &String::from_str(env, "Cross-Chain Vault"),
            &String::from_str(env, "Revocation broadcast test"),
            &vec![env, Address::generate(env)],
            &1,
        );
        let doc_id = client.add_document(
            &creator,
            &vault_id,
            &String::from_str(env, "meta"),
            &String::from_str(env, "QmHash"),
            &AccessLevel::Read,
            &ReleaseCondition::Anytime,
            &vec![env, creator.clone()],
            &vec![env, String::from_str(env, "share")],
        );
        let req_id = client.request_access(&requester, &doc_id);
        client.approve_access(&creator, &req_id, &None);

        let evm_keys = generate_evm_keypair(env, 42);
        let vault_gid = BytesN::from_array(env, &[9u8; 32]);
        client.link_cross_chain_vault(&creator, &vault_id, &vault_gid, &evm_keys.address);

        (client, requester, vault_id, doc_id, evm_keys, vault_gid)
    }

    #[test]
    fn test_relay_revoke_access_applies_evm_signed_revocation() {
        let env = Env::default();
        let (client, requester, _vault_id, doc_id, evm_keys, vault_gid) = setup_linked_vault(&env);

        assert!(client.get_document(&doc_id).is_some());

        let nonce = 1u64;
        let (sig, recovery_id) = sign_revocation(
            &env,
            &evm_keys.signing_key,
            &vault_gid,
            doc_id,
            &evm_keys.address,
            &requester,
            nonce,
        );

        client.relay_revoke_access(
            &vault_gid,
            &doc_id,
            &evm_keys.address,
            &requester,
            &nonce,
            &sig,
            &recovery_id,
        );

        // Access was actually cleared: a fresh request now succeeds instead
        // of panicking on "Already has access".
        let new_req_id = client.request_access(&requester, &doc_id);
        assert!(new_req_id > 0);
    }

    #[test]
    #[should_panic(expected = "Stale or replayed revocation nonce")]
    fn test_relay_revoke_access_rejects_replayed_nonce() {
        let env = Env::default();
        let (client, requester, _vault_id, doc_id, evm_keys, vault_gid) = setup_linked_vault(&env);

        let nonce = 1u64;
        let (sig, recovery_id) = sign_revocation(
            &env,
            &evm_keys.signing_key,
            &vault_gid,
            doc_id,
            &evm_keys.address,
            &requester,
            nonce,
        );

        client.relay_revoke_access(
            &vault_gid,
            &doc_id,
            &evm_keys.address,
            &requester,
            &nonce,
            &sig,
            &recovery_id,
        );
        // Replaying the exact same signed message must be rejected.
        client.relay_revoke_access(
            &vault_gid,
            &doc_id,
            &evm_keys.address,
            &requester,
            &nonce,
            &sig,
            &recovery_id,
        );
    }

    #[test]
    #[should_panic(expected = "Signature not from linked cross-chain revoker")]
    fn test_relay_revoke_access_rejects_unauthorized_signer() {
        let env = Env::default();
        let (client, requester, _vault_id, doc_id, _evm_keys, vault_gid) = setup_linked_vault(&env);

        // A different EVM key signs the same payload - not the vault's
        // registered cross-chain revoker.
        let attacker_keys = generate_evm_keypair(&env, 99);
        let nonce = 1u64;
        let (sig, recovery_id) = sign_revocation(
            &env,
            &attacker_keys.signing_key,
            &vault_gid,
            doc_id,
            &attacker_keys.address,
            &requester,
            nonce,
        );

        client.relay_revoke_access(
            &vault_gid,
            &doc_id,
            &attacker_keys.address,
            &requester,
            &nonce,
            &sig,
            &recovery_id,
        );
    }
}

/// Upgrade governance: contract-wide multi-sig admin authorization for
/// `upgrade_contract` (Wasm code replacement) and `migrate`.
mod upgrade_governance {
    use super::*;
    use soroban_sdk::Error as SdkError;

    /// The "new version" of the contract, imported as raw Wasm and uploaded
    /// via `env.deployer().upload_contract_wasm` to give `upgrade_contract`
    /// a real, already-present hash to swap to. Built by CI before this
    /// crate's tests run (see `.github/workflows/fuzzing.yml` and
    /// `.github/workflows/coverage.yml`); see
    /// `contracts-stellar/upgrade_fixture/README.md` to build it locally.
    mod new_contract {
        soroban_sdk::contractimport!(
            file = "upgrade_fixture/target/wasm32-unknown-unknown/release/spoovault_stellar_upgrade_fixture.wasm"
        );
    }

    fn install_new_wasm(env: &Env) -> BytesN<32> {
        env.deployer().upload_contract_wasm(new_contract::WASM)
    }

    #[test]
    fn test_init_admins_records_configured_set_and_threshold() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, SpooVaultStellar);
        let client = SpooVaultStellarClient::new(&env, &contract_id);

        let admin_a = Address::generate(&env);
        let admin_b = Address::generate(&env);
        client.init_admins(&vec![&env, admin_a.clone(), admin_b.clone()], &2);

        assert_eq!(client.get_admins(), vec![&env, admin_a, admin_b]);
        assert_eq!(client.get_admin_threshold(), 2);
    }

    #[test]
    #[should_panic(expected = "Admins already initialized")]
    fn test_init_admins_rejects_reinitialization() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, SpooVaultStellar);
        let client = SpooVaultStellarClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        client.init_admins(&vec![&env, admin.clone()], &1);
        client.init_admins(&vec![&env, admin], &1);
    }

    #[test]
    #[should_panic(expected = "Invalid admin threshold")]
    fn test_init_admins_rejects_threshold_above_admin_count() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, SpooVaultStellar);
        let client = SpooVaultStellarClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        client.init_admins(&vec![&env, admin], &2);
    }

    #[test]
    #[should_panic(expected = "Duplicate admin found")]
    fn test_init_admins_rejects_duplicate_admin() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, SpooVaultStellar);
        let client = SpooVaultStellarClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        client.init_admins(&vec![&env, admin.clone(), admin], &1);
    }

    #[test]
    fn test_upgrade_contract_rejects_non_admin() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, SpooVaultStellar);
        let client = SpooVaultStellarClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        client.init_admins(&vec![&env, admin], &1);

        let not_admin = Address::generate(&env);
        let some_hash = BytesN::from_array(&env, &[7u8; 32]);
        let result = client.try_upgrade_contract(&not_admin, &some_hash);
        assert_eq!(
            result,
            Err(Ok(SdkError::from_contract_error(
                UpgradeError::UnauthorizedAdmin as u32
            )))
        );
    }

    #[test]
    fn test_upgrade_contract_rejects_before_admins_initialized() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, SpooVaultStellar);
        let client = SpooVaultStellarClient::new(&env, &contract_id);

        let caller = Address::generate(&env);
        let some_hash = BytesN::from_array(&env, &[7u8; 32]);
        let result = client.try_upgrade_contract(&caller, &some_hash);
        assert_eq!(
            result,
            Err(Ok(SdkError::from_contract_error(
                UpgradeError::NotInitialized as u32
            )))
        );
    }

    #[test]
    fn test_upgrade_contract_does_not_swap_before_threshold_is_met() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, SpooVaultStellar);
        let client = SpooVaultStellarClient::new(&env, &contract_id);

        let admin_a = Address::generate(&env);
        let admin_b = Address::generate(&env);
        client.init_admins(&vec![&env, admin_a.clone(), admin_b], &2);

        // Only one of the two required admins approves - the hash need not
        // be a real uploaded Wasm blob, since the swap must not be
        // attempted yet.
        let some_hash = BytesN::from_array(&env, &[7u8; 32]);
        client.upgrade_contract(&admin_a, &some_hash);

        assert_eq!(client.version(), 1);
    }

    #[test]
    fn test_upgrade_contract_rejects_duplicate_approval_from_same_admin() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, SpooVaultStellar);
        let client = SpooVaultStellarClient::new(&env, &contract_id);

        let admin_a = Address::generate(&env);
        let admin_b = Address::generate(&env);
        client.init_admins(&vec![&env, admin_a.clone(), admin_b], &2);

        let some_hash = BytesN::from_array(&env, &[7u8; 32]);
        client.upgrade_contract(&admin_a, &some_hash);

        let result = client.try_upgrade_contract(&admin_a, &some_hash);
        assert_eq!(
            result,
            Err(Ok(SdkError::from_contract_error(
                UpgradeError::AlreadyApproved as u32
            )))
        );
    }

    #[test]
    fn test_upgrade_contract_swaps_wasm_and_preserves_existing_state_once_threshold_met() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, SpooVaultStellar);
        let client = SpooVaultStellarClient::new(&env, &contract_id);

        // Existing state created under the v1 code, which must survive the
        // upgrade untouched (Soroban storage is keyed by contract ID, not
        // by the executing Wasm).
        let creator = Address::generate(&env);
        let guardian = Address::generate(&env);
        let vault_id = client.create_vault(
            &creator,
            &String::from_str(&env, "Pre-upgrade Vault"),
            &String::from_str(&env, "Created before the code swap"),
            &vec![&env, guardian],
            &1,
        );

        let admin_a = Address::generate(&env);
        let admin_b = Address::generate(&env);
        client.init_admins(&vec![&env, admin_a.clone(), admin_b.clone()], &2);

        let new_wasm_hash = install_new_wasm(&env);
        client.upgrade_contract(&admin_a, &new_wasm_hash);
        assert_eq!(client.version(), 1, "must not swap before the threshold is met");

        client.upgrade_contract(&admin_b, &new_wasm_hash);

        // Existing persistent state survived the Wasm swap.
        let preserved_vault = client.get_vault(&vault_id).expect("vault must survive upgrade");
        assert_eq!(preserved_vault.name, String::from_str(&env, "Pre-upgrade Vault"));

        // The code itself was actually replaced: a client built against the
        // new contract's interface now works against this same contract ID,
        // and exposes the new version/behavior.
        let upgraded_client = new_contract::Client::new(&env, &contract_id);
        assert_eq!(upgraded_client.version(), 2);
        assert_eq!(upgraded_client.new_feature(), 1_010_101);
    }

    #[test]
    fn test_migrate_rejects_non_admin() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, SpooVaultStellar);
        let client = SpooVaultStellarClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        client.init_admins(&vec![&env, admin], &1);

        let not_admin = Address::generate(&env);
        let result = client.try_migrate(&not_admin);
        assert_eq!(
            result,
            Err(Ok(SdkError::from_contract_error(
                UpgradeError::UnauthorizedAdmin as u32
            )))
        );
    }

    #[test]
    fn test_migrate_is_idempotent_for_admin_at_current_schema_version() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, SpooVaultStellar);
        let client = SpooVaultStellarClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        client.init_admins(&vec![&env, admin.clone()], &1);

        // Schema is already at CURRENT_SCHEMA_VERSION post-init, so this is
        // a no-op both times - repeated invocation must not panic.
        client.migrate(&admin);
        client.migrate(&admin);
    }
}
