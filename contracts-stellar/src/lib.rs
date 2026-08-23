#![no_std]
// Soroban SDK macros emit `cfg(testutils)` which newer rustc check-cfg flags.
#![allow(unexpected_cfgs)]
// Public contract entrypoints intentionally take many args (env + auth + payload).
#![allow(clippy::too_many_arguments)]
use soroban_sdk::{
    auth::{ContractContext, InvokerContractAuthEntry, SubContractInvocation},
    contract, contracterror, contractimpl, contracttype, panic_with_error,
    xdr::ToXdr,
    Address, Bytes, BytesN, Env, IntoVal, String, Symbol, Val, Vec,
};

/// Zero-pads a `u64` into a 32-byte big-endian word, matching how Solidity's
/// `abi.encodePacked` serializes a `uint256`.
fn u256_be(value: u64) -> [u8; 32] {
    let mut buf = [0u8; 32];
    buf[24..32].copy_from_slice(&value.to_be_bytes());
    buf
}

/// Ledger constants for TTL extension thresholds and bump amounts (~5s per ledger)
/// ~7 days = 120,960 ledgers
pub const INSTANCE_LIFETIME_THRESHOLD: u32 = 120_960;
/// ~30 days = 518,400 ledgers
pub const INSTANCE_BUMP_AMOUNT: u32 = 518_400;
/// ~7 days = 120,960 ledgers
pub const PERSISTENT_LIFETIME_THRESHOLD: u32 = 120_960;
/// ~30 days = 518,400 ledgers
pub const PERSISTENT_BUMP_AMOUNT: u32 = 518_400;

/// Current persistent-storage schema version. Bumped whenever an upgrade
/// changes the meaning/layout of existing storage; `migrate` transforms
/// storage from a prior version up to this one and is a no-op once the
/// stored `DataKey::SchemaVersion` already matches.
pub const CURRENT_SCHEMA_VERSION: u32 = 1;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum UpgradeError {
    /// `init_admins` has not been called yet, so there is no admin set to
    /// authorize against.
    NotInitialized = 1,
    /// The caller is not a member of the configured admin set.
    UnauthorizedAdmin = 2,
    /// The caller already approved the currently pending upgrade proposal.
    AlreadyApproved = 3,
}

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessLevel {
    Read = 0,
    ReadWrite = 1,
    Admin = 2,
}

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseCondition {
    Anytime = 0,
    LiveOnly = 1,
    EmergencyOnly = 2,
    PostDeathOnly = 3,
}

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestStatus {
    Pending = 0,
    Approved = 1,
    Rejected = 2,
    Expired = 3,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct Vault {
    pub id: u64,
    pub creator: Address,
    pub name: String,
    pub description: String,
    pub guardians: Vec<Address>,
    pub approval_threshold: u32,
    pub is_active: bool,
    pub created_at: u64,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct Document {
    pub id: u64,
    pub vault_id: u64,
    pub encrypted_metadata: String,
    pub ipfs_hash: String,
    pub uploaded_by: Address,
    pub uploaded_at: u64,
    pub required_access: AccessLevel,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct AccessRequest {
    pub request_id: u64,
    pub document_id: u64,
    pub requester: Address,
    pub approved_by: Vec<Address>,
    pub status: RequestStatus,
    pub expires_at: u64,
    pub created_at: u64,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct GuardianInvite {
    pub guardian: Address,
    pub vault_id: u64,
    pub accepted: bool,
    pub expires_at: u64,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct VaultReleaseState {
    pub emergency_mode: bool,
    pub inactivity_period: u64,
    pub last_proof_of_life: u64,
}

/// A pending contract-code upgrade awaiting the configured admin threshold
/// of distinct approvals before the Wasm swap is executed.
#[contracttype]
#[derive(Clone, Debug)]
pub struct UpgradeProposal {
    pub new_wasm_hash: BytesN<32>,
    pub approved_by: Vec<Address>,
}

#[contracttype]
pub enum DataKey {
    VaultCount,
    DocCount,
    ReqCount,
    Vault(u64),
    Doc(u64),
    Request(u64),
    IsGuardian(u64, Address),
    HasAccess(u64, Address),
    AccessLvl(u64, Address),
    Invites(Address),
    ApprovedReq(u64, Address),
    LatestReq(u64, Address),
    PubKey(Address),
    GShare(u64, Address),
    BShare(u64, Address),
    DocReleaseCond(u64),
    ReleaseState(u64),
    // Optional external registry contract notified on document access grants
    AccessRegistry(u64),
    // Cross-Chain Identity Lookup Map
    EvmToStellar(String),
    StellarToEvm(Address),
    EvmToPubKey(String),
    // Cross-Chain Revocation Broadcast Engine
    VaultGid(BytesN<32>),
    CrossChainRevoker(u64),
    RevocationNonce(BytesN<32>, u64, Address),
    // Upgrade governance
    Admins,
    AdminThreshold,
    UpgradeProposal,
    SchemaVersion,
}

#[contract]
pub struct SpooVaultStellar;

#[contractimpl]
impl SpooVaultStellar {
    /// Extend instance storage TTL
    pub fn extend_contract_ttl(env: Env) {
        Self::bump_instance(&env);
    }

    /// Extend persistent storage TTL for a vault and its state
    pub fn extend_vault_ttl(env: Env, vault_id: u64) {
        Self::bump_instance(&env);
        let vault_key = DataKey::Vault(vault_id);
        if env.storage().persistent().has(&vault_key) {
            Self::bump_persistent(&env, &vault_key);
            Self::bump_persistent(&env, &DataKey::ReleaseState(vault_id));
        }
    }

    /// Extend persistent storage TTL for a document
    pub fn extend_document_ttl(env: Env, document_id: u64) {
        Self::bump_instance(&env);
        let doc_key = DataKey::Doc(document_id);
        if env.storage().persistent().has(&doc_key) {
            Self::bump_persistent(&env, &doc_key);
            Self::bump_persistent(&env, &DataKey::DocReleaseCond(document_id));
        }
    }

    /// Extend persistent storage TTL for an access request
    pub fn extend_request_ttl(env: Env, request_id: u64) {
        Self::bump_instance(&env);
        let req_key = DataKey::Request(request_id);
        if env.storage().persistent().has(&req_key) {
            Self::bump_persistent(&env, &req_key);
        }
    }

    /// Contract code version. Bumped by whoever ships a new Wasm build;
    /// used by upgrade integration tests to confirm a Wasm swap actually
    /// took effect (a fresh client built against the new build's ABI will
    /// observe the new version).
    pub fn version(_env: Env) -> u32 {
        1
    }

    // -------------------------------------------------------------------
    // Upgrade governance
    //
    // A dedicated, contract-wide admin set (distinct from any vault's
    // per-vault guardians) authorizes Wasm code upgrades. `upgrade_contract`
    // mirrors `approve_access`'s established pattern in this contract: each
    // admin calls the same entry point once, their approval is recorded,
    // and once the configured threshold of distinct admins has approved the
    // *same* `new_wasm_hash`, the swap executes automatically within that
    // triggering call - there is no separate "propose" vs "execute" step.
    // -------------------------------------------------------------------

    /// One-time admin governance bootstrap. Every supplied admin must
    /// individually authorize this call (rather than trusting a single
    /// deployer to unilaterally hand admin power to addresses that never
    /// consented). Reverts if admins are already initialized.
    pub fn init_admins(env: Env, admins: Vec<Address>, threshold: u32) {
        assert!(
            !env.storage().instance().has(&DataKey::Admins),
            "Admins already initialized"
        );

        let mut processed = Vec::new(&env);
        for i in 0..admins.len() {
            let admin = admins.get(i).unwrap();
            admin.require_auth();
            assert!(!processed.contains(&admin), "Duplicate admin found");
            processed.push_back(admin.clone());
        }

        assert!(
            threshold > 0 && threshold <= admins.len(),
            "Invalid admin threshold"
        );

        env.storage().instance().set(&DataKey::Admins, &admins);
        env.storage()
            .instance()
            .set(&DataKey::AdminThreshold, &threshold);
        env.storage()
            .instance()
            .set(&DataKey::SchemaVersion, &CURRENT_SCHEMA_VERSION);
        Self::bump_instance(&env);
    }

    /// Returns the configured admin set (empty if `init_admins` has not
    /// been called yet).
    pub fn get_admins(env: Env) -> Vec<Address> {
        env.storage()
            .instance()
            .get(&DataKey::Admins)
            .unwrap_or_else(|| Vec::new(&env))
    }

    /// Returns the configured admin approval threshold (0 if `init_admins`
    /// has not been called yet).
    pub fn get_admin_threshold(env: Env) -> u32 {
        env.storage()
            .instance()
            .get(&DataKey::AdminThreshold)
            .unwrap_or(0)
    }

    /// Propose or co-sign a Wasm code upgrade to `new_wasm_hash`.
    ///
    /// `new_wasm_hash` must already be present on the ledger (uploaded via
    /// `env.deployer().upload_contract_wasm`). Each call by a distinct
    /// configured admin counts as one approval toward the configured
    /// threshold. A call proposing a different hash than the currently
    /// pending proposal (or the first call) starts a fresh proposal with
    /// only that admin's approval recorded. Once enough distinct admins
    /// have approved the *same* hash, the Wasm code is swapped atomically
    /// within this same invocation via
    /// `env.deployer().update_current_contract_wasm` - existing instance
    /// and persistent storage is untouched by the swap itself (Soroban
    /// storage is keyed by contract ID, not by the executing Wasm code), so
    /// no data migration is required unless the new code changes how
    /// existing storage should be interpreted (see `migrate`).
    ///
    /// Reverts with `UpgradeError::UnauthorizedAdmin` if `admin` is not in
    /// the configured admin set, or `UpgradeError::NotInitialized` if
    /// `init_admins` has not been called yet.
    pub fn upgrade_contract(env: Env, admin: Address, new_wasm_hash: BytesN<32>) {
        admin.require_auth();
        Self::bump_instance(&env);

        let admins: Vec<Address> = env
            .storage()
            .instance()
            .get(&DataKey::Admins)
            .unwrap_or_else(|| panic_with_error!(&env, UpgradeError::NotInitialized));
        if !admins.contains(&admin) {
            panic_with_error!(&env, UpgradeError::UnauthorizedAdmin);
        }

        let threshold: u32 = env
            .storage()
            .instance()
            .get(&DataKey::AdminThreshold)
            .unwrap_or(0);

        let mut proposal: UpgradeProposal = env
            .storage()
            .instance()
            .get(&DataKey::UpgradeProposal)
            .unwrap_or(UpgradeProposal {
                new_wasm_hash: new_wasm_hash.clone(),
                approved_by: Vec::new(&env),
            });

        // A proposal for a different hash supersedes any stale pending one.
        if proposal.new_wasm_hash != new_wasm_hash {
            proposal = UpgradeProposal {
                new_wasm_hash: new_wasm_hash.clone(),
                approved_by: Vec::new(&env),
            };
        }

        if proposal.approved_by.contains(&admin) {
            panic_with_error!(&env, UpgradeError::AlreadyApproved);
        }
        proposal.approved_by.push_back(admin.clone());

        if proposal.approved_by.len() >= threshold {
            env.storage().instance().remove(&DataKey::UpgradeProposal);
            env.deployer()
                .update_current_contract_wasm(new_wasm_hash.clone());
            env.events()
                .publish((Symbol::new(&env, "contract_upgraded"),), new_wasm_hash);
        } else {
            env.storage()
                .instance()
                .set(&DataKey::UpgradeProposal, &proposal);
        }
    }

    /// Post-upgrade storage migration hook, callable by any configured
    /// admin. Idempotent per schema version: transforms persistent storage
    /// laid out by a prior contract version and bumps
    /// `DataKey::SchemaVersion` so re-invocation after that is a no-op.
    /// Currently a no-op body (schema version 1 is the only version that
    /// has existed); a future upgrade that changes the storage layout
    /// implements its transformation here and bumps `CURRENT_SCHEMA_VERSION`.
    ///
    /// Reverts with `UpgradeError::UnauthorizedAdmin` if `admin` is not in
    /// the configured admin set.
    pub fn migrate(env: Env, admin: Address) {
        admin.require_auth();
        Self::bump_instance(&env);

        let admins: Vec<Address> = env
            .storage()
            .instance()
            .get(&DataKey::Admins)
            .unwrap_or_else(|| panic_with_error!(&env, UpgradeError::NotInitialized));
        if !admins.contains(&admin) {
            panic_with_error!(&env, UpgradeError::UnauthorizedAdmin);
        }

        let current: u32 = env
            .storage()
            .instance()
            .get(&DataKey::SchemaVersion)
            .unwrap_or(1);
        if current >= CURRENT_SCHEMA_VERSION {
            return;
        }

        // Storage-layout transformations for schema versions below
        // CURRENT_SCHEMA_VERSION are added here as the schema evolves.

        env.storage()
            .instance()
            .set(&DataKey::SchemaVersion, &CURRENT_SCHEMA_VERSION);
    }

    /// Register a user's encryption public key
    pub fn register_public_key(env: Env, user: Address, public_key: String) {
        user.require_auth();
        Self::bump_instance(&env);

        let key = DataKey::PubKey(user.clone());
        env.storage().persistent().set(&key, &public_key);
        Self::bump_persistent(&env, &key);
    }

    /// Retrieve public key for a user
    pub fn get_public_key(env: Env, user: Address) -> Option<String> {
        Self::bump_instance(&env);
        let key = DataKey::PubKey(user);
        let val: Option<String> = env.storage().persistent().get(&key);
        if val.is_some() {
            Self::bump_persistent(&env, &key);
        }
        val
    }

    /// Register linked cross-chain identity (EVM Address <-> Stellar Address & Public Key)
    pub fn register_cross_chain_identity(
        env: Env,
        stellar_user: Address,
        evm_address: String,
        encryption_pubkey: Option<String>,
    ) {
        stellar_user.require_auth();
        assert!(evm_address.len() == 42, "Invalid EVM address length");
        Self::bump_instance(&env);

        let evm_to_stellar_key = DataKey::EvmToStellar(evm_address.clone());
        let stellar_to_evm_key = DataKey::StellarToEvm(stellar_user.clone());

        env.storage().persistent().set(&evm_to_stellar_key, &stellar_user);
        env.storage().persistent().set(&stellar_to_evm_key, &evm_address);

        Self::bump_persistent(&env, &evm_to_stellar_key);
        Self::bump_persistent(&env, &stellar_to_evm_key);

        if let Some(pubkey) = encryption_pubkey {
            let evm_to_pubkey_key = DataKey::EvmToPubKey(evm_address);
            let stellar_pubkey_key = DataKey::PubKey(stellar_user);

            env.storage().persistent().set(&evm_to_pubkey_key, &pubkey);
            env.storage().persistent().set(&stellar_pubkey_key, &pubkey);

            Self::bump_persistent(&env, &evm_to_pubkey_key);
            Self::bump_persistent(&env, &stellar_pubkey_key);
        }
    }

    /// Resolve EVM address to linked Stellar Address
    pub fn resolve_evm_to_stellar(env: Env, evm_address: String) -> Option<Address> {
        Self::bump_instance(&env);
        let key = DataKey::EvmToStellar(evm_address);
        let addr: Option<Address> = env.storage().persistent().get(&key);
        if addr.is_some() {
            Self::bump_persistent(&env, &key);
        }
        addr
    }

    /// Resolve Stellar Address to linked EVM Address
    pub fn resolve_stellar_to_evm(env: Env, stellar_user: Address) -> Option<String> {
        Self::bump_instance(&env);
        let key = DataKey::StellarToEvm(stellar_user);
        let evm: Option<String> = env.storage().persistent().get(&key);
        if evm.is_some() {
            Self::bump_persistent(&env, &key);
        }
        evm
    }

    /// Resolve EVM address directly to its linked Encryption Public Key
    pub fn resolve_evm_to_public_key(env: Env, evm_address: String) -> Option<String> {
        Self::bump_instance(&env);
        let key = DataKey::EvmToPubKey(evm_address.clone());
        let pubkey: Option<String> = env.storage().persistent().get(&key);
        if pubkey.is_some() {
            Self::bump_persistent(&env, &key);
            return pubkey;
        }

        // Fallback: If EVM -> Stellar exists, resolve Stellar -> PubKey
        if let Some(stellar_addr) = Self::resolve_evm_to_stellar(env.clone(), evm_address) {
            return Self::get_public_key(env, stellar_addr);
        }

        None
    }

    /// Create a new Vault.
    ///
    /// `creator` and each entry in `guardians` are plain `Address` values, so
    /// they may be either a raw Stellar keypair (G-account) or a deployed
    /// contract address (a multisig / custom account-abstraction signer, or
    /// any other contract implementing `soroban_sdk::auth::CustomAccountInterface`).
    /// `require_auth` resolves against whichever kind of address is supplied,
    /// so no special-casing is needed here for contract-account guardians.
    pub fn create_vault(
        env: Env,
        creator: Address,
        name: String,
        description: String,
        guardians: Vec<Address>,
        approval_threshold: u32,
    ) -> u64 {
        creator.require_auth();
        Self::bump_instance(&env);

        // Basic validations
        let mut ext_guardian_count = 0;
        let mut processed = Vec::new(&env);

        for i in 0..guardians.len() {
            let guardian = guardians.get(i).unwrap();
            // Check duplicates
            assert!(!processed.contains(&guardian), "Duplicate guardian found");
            processed.push_back(guardian.clone());

            if guardian != creator {
                ext_guardian_count += 1;
            }
        }

        assert!(ext_guardian_count > 0, "At least one external guardian required");
        let total_guardians = ext_guardian_count + 1;
        assert!(
            approval_threshold > 0 && approval_threshold <= total_guardians,
            "Invalid approval threshold"
        );

        let vault_count: u64 = env.storage().instance().get(&DataKey::VaultCount).unwrap_or(0);
        let next_vault_id = vault_count + 1;
        env.storage().instance().set(&DataKey::VaultCount, &next_vault_id);

        let mut actual_guardians = Vec::new(&env);
        actual_guardians.push_back(creator.clone());

        let vault = Vault {
            id: next_vault_id,
            creator: creator.clone(),
            name,
            description,
            guardians: actual_guardians,
            approval_threshold,
            is_active: true,
            created_at: env.ledger().timestamp(),
        };

        let vault_key = DataKey::Vault(next_vault_id);
        let is_guardian_key = DataKey::IsGuardian(next_vault_id, creator.clone());
        env.storage().persistent().set(&vault_key, &vault);
        env.storage().persistent().set(&is_guardian_key, &true);
        Self::bump_persistent(&env, &vault_key);
        Self::bump_persistent(&env, &is_guardian_key);

        // Configure release state defaults
        let release_state = VaultReleaseState {
            emergency_mode: false,
            inactivity_period: 30 * 24 * 60 * 60, // 30 days in seconds
            last_proof_of_life: env.ledger().timestamp(),
        };
        let release_key = DataKey::ReleaseState(next_vault_id);
        env.storage().persistent().set(&release_key, &release_state);
        Self::bump_persistent(&env, &release_key);

        // Record invites for external guardians
        for i in 0..guardians.len() {
            let guardian = guardians.get(i).unwrap();
            if guardian == creator {
                continue;
            }

            let invites_key = DataKey::Invites(guardian.clone());
            let mut user_invites: Vec<GuardianInvite> = env
                .storage()
                .persistent()
                .get(&invites_key)
                .unwrap_or_else(|| Vec::new(&env));

            user_invites.push_back(GuardianInvite {
                guardian: guardian.clone(),
                vault_id: next_vault_id,
                accepted: false,
                expires_at: env.ledger().timestamp() + 7 * 24 * 60 * 60, // 7 days
            });

            env.storage().persistent().set(&invites_key, &user_invites);
            Self::bump_persistent(&env, &invites_key);
        }

        next_vault_id
    }

    /// Accept guardian invitation
    pub fn accept_guardian_invite(env: Env, guardian: Address, vault_id: u64) {
        guardian.require_auth();
        Self::bump_instance(&env);

        let vault_key = DataKey::Vault(vault_id);
        let mut vault: Vault = env
            .storage()
            .persistent()
            .get(&vault_key)
            .expect("Vault does not exist");
        assert!(vault.is_active, "Vault not active");

        let is_guard_key = DataKey::IsGuardian(vault_id, guardian.clone());
        let is_guard: bool = env
            .storage()
            .persistent()
            .get(&is_guard_key)
            .unwrap_or(false);
        assert!(!is_guard, "Already guardian");

        let invites_key = DataKey::Invites(guardian.clone());
        let mut user_invites: Vec<GuardianInvite> = env
            .storage()
            .persistent()
            .get(&invites_key)
            .expect("No invites for user");

        let mut accepted = false;
        for i in 0..user_invites.len() {
            let mut invite = user_invites.get(i).unwrap();
            if invite.vault_id == vault_id && !invite.accepted {
                assert!(env.ledger().timestamp() < invite.expires_at, "Invite expired");
                invite.accepted = true;
                user_invites.set(i, invite);
                accepted = true;
                break;
            }
        }

        assert!(accepted, "No valid invite found");
        env.storage().persistent().set(&invites_key, &user_invites);
        env.storage().persistent().set(&is_guard_key, &true);
        Self::bump_persistent(&env, &invites_key);
        Self::bump_persistent(&env, &is_guard_key);

        vault.guardians.push_back(guardian);
        env.storage().persistent().set(&vault_key, &vault);
        Self::bump_persistent(&env, &vault_key);
    }

    /// Add a document metadata and storage hash
    pub fn add_document(
        env: Env,
        uploader: Address,
        vault_id: u64,
        encrypted_metadata: String,
        ipfs_hash: String,
        required_access: AccessLevel,
        release_condition: ReleaseCondition,
        guardians_list: Vec<Address>,
        shares: Vec<String>,
    ) -> u64 {
        uploader.require_auth();
        Self::bump_instance(&env);

        let is_guard: bool = env
            .storage()
            .persistent()
            .get(&DataKey::IsGuardian(vault_id, uploader.clone()))
            .unwrap_or(false);
        assert!(is_guard, "Only guardians can upload documents");
        assert!(!ipfs_hash.is_empty(), "IPFS hash required");
        assert!(
            guardians_list.len() == shares.len(),
            "Guardians list and shares count mismatch"
        );

        let doc_count: u64 = env.storage().instance().get(&DataKey::DocCount).unwrap_or(0);
        let next_doc_id = doc_count + 1;
        env.storage().instance().set(&DataKey::DocCount, &next_doc_id);

        let doc = Document {
            id: next_doc_id,
            vault_id,
            encrypted_metadata,
            ipfs_hash,
            uploaded_by: uploader.clone(),
            uploaded_at: env.ledger().timestamp(),
            required_access,
        };

        let doc_key = DataKey::Doc(next_doc_id);
        let rel_key = DataKey::DocReleaseCond(next_doc_id);
        let access_key = DataKey::HasAccess(next_doc_id, uploader.clone());
        let lvl_key = DataKey::AccessLvl(next_doc_id, uploader);

        env.storage().persistent().set(&doc_key, &doc);
        env.storage().persistent().set(&rel_key, &release_condition);
        env.storage().persistent().set(&access_key, &true);
        env.storage().persistent().set(&lvl_key, &required_access);

        Self::bump_persistent(&env, &doc_key);
        Self::bump_persistent(&env, &rel_key);
        Self::bump_persistent(&env, &access_key);
        Self::bump_persistent(&env, &lvl_key);

        // Store guardian shares
        for i in 0..guardians_list.len() {
            let guardian = guardians_list.get(i).unwrap();
            let share = shares.get(i).unwrap();
            let gshare_key = DataKey::GShare(next_doc_id, guardian);
            env.storage().persistent().set(&gshare_key, &share);
            Self::bump_persistent(&env, &gshare_key);
        }

        next_doc_id
    }

    /// Request document access
    pub fn request_access(env: Env, requester: Address, document_id: u64) -> u64 {
        requester.require_auth();
        Self::bump_instance(&env);

        let doc_key = DataKey::Doc(document_id);
        let doc: Document = env
            .storage()
            .persistent()
            .get(&doc_key)
            .expect("Document not found");
        Self::bump_persistent(&env, &doc_key);

        let has_acc: bool = env
            .storage()
            .persistent()
            .get(&DataKey::HasAccess(document_id, requester.clone()))
            .unwrap_or(false);
        assert!(!has_acc, "Already has access");

        // Verify release condition
        let cond: ReleaseCondition = env
            .storage()
            .persistent()
            .get(&DataKey::DocReleaseCond(document_id))
            .unwrap_or(ReleaseCondition::Anytime);

        assert!(
            Self::is_release_condition_satisfied(&env, doc.vault_id, cond),
            "Release condition locked"
        );

        let req_count: u64 = env.storage().instance().get(&DataKey::ReqCount).unwrap_or(0);
        let next_req_id = req_count + 1;
        env.storage().instance().set(&DataKey::ReqCount, &next_req_id);

        let access_req = AccessRequest {
            request_id: next_req_id,
            document_id,
            requester: requester.clone(),
            approved_by: Vec::new(&env),
            status: RequestStatus::Pending,
            expires_at: env.ledger().timestamp() + 3 * 24 * 60 * 60, // 3 days
            created_at: env.ledger().timestamp(),
        };

        let req_key = DataKey::Request(next_req_id);
        let latest_req_key = DataKey::LatestReq(document_id, requester);
        env.storage().persistent().set(&req_key, &access_req);
        env.storage().persistent().set(&latest_req_key, &next_req_id);

        Self::bump_persistent(&env, &req_key);
        Self::bump_persistent(&env, &latest_req_key);

        next_req_id
    }

    /// Approve document access request by a guardian
    pub fn approve_access(
        env: Env,
        approver: Address,
        request_id: u64,
        beneficiary_share: Option<String>,
    ) {
        approver.require_auth();
        Self::bump_instance(&env);

        let req_key = DataKey::Request(request_id);
        let mut request: AccessRequest = env
            .storage()
            .persistent()
            .get(&req_key)
            .expect("Request not found");
        assert!(
            request.status == RequestStatus::Pending,
            "Request not pending"
        );
        assert!(
            env.ledger().timestamp() < request.expires_at,
            "Request expired"
        );

        let doc_key = DataKey::Doc(request.document_id);
        let doc: Document = env
            .storage()
            .persistent()
            .get(&doc_key)
            .expect("Document not found");

        let vault_key = DataKey::Vault(doc.vault_id);
        let vault: Vault = env
            .storage()
            .persistent()
            .get(&vault_key)
            .expect("Vault not found");

        let is_guard_key = DataKey::IsGuardian(doc.vault_id, approver.clone());
        let is_guard: bool = env
            .storage()
            .persistent()
            .get(&is_guard_key)
            .unwrap_or(false);
        assert!(is_guard, "Only guardians can approve access");

        let approved_req_key = DataKey::ApprovedReq(request_id, approver.clone());
        let already_approved: bool = env
            .storage()
            .persistent()
            .get(&approved_req_key)
            .unwrap_or(false);
        assert!(!already_approved, "Already approved");

        env.storage().persistent().set(&approved_req_key, &true);
        Self::bump_persistent(&env, &approved_req_key);

        request.approved_by.push_back(approver.clone());

        if let Some(share) = beneficiary_share {
            let bshare_key = DataKey::BShare(request_id, approver);
            env.storage().persistent().set(&bshare_key, &share);
            Self::bump_persistent(&env, &bshare_key);
        }

        if request.approved_by.len() >= vault.approval_threshold {
            request.status = RequestStatus::Approved;
            let acc_key = DataKey::HasAccess(request.document_id, request.requester.clone());
            let lvl_key = DataKey::AccessLvl(request.document_id, request.requester.clone());
            env.storage().persistent().set(&acc_key, &true);
            env.storage().persistent().set(&lvl_key, &doc.required_access);
            Self::bump_persistent(&env, &acc_key);
            Self::bump_persistent(&env, &lvl_key);

            let registry_key = DataKey::AccessRegistry(doc.vault_id);
            if let Some(registry) = env.storage().persistent().get::<_, Address>(&registry_key) {
                Self::bump_persistent(&env, &registry_key);
                Self::notify_access_registry(
                    &env,
                    &registry,
                    request.document_id,
                    &request.requester,
                );
            }
        }

        env.storage().persistent().set(&req_key, &request);
        Self::bump_persistent(&env, &req_key);
    }

    /// Record proof of life for inactivity check
    pub fn prove_life(env: Env, owner: Address, vault_id: u64) {
        owner.require_auth();
        Self::bump_instance(&env);

        let vault_key = DataKey::Vault(vault_id);
        let vault: Vault = env
            .storage()
            .persistent()
            .get(&vault_key)
            .expect("Vault not found");
        assert!(vault.creator == owner, "Only creator can record proof of life");
        assert!(vault.is_active, "Vault not active");

        let rel_key = DataKey::ReleaseState(vault_id);
        let mut state: VaultReleaseState = env
            .storage()
            .persistent()
            .get(&rel_key)
            .unwrap();
        state.last_proof_of_life = env.ledger().timestamp();
        env.storage().persistent().set(&rel_key, &state);

        Self::bump_persistent(&env, &vault_key);
        Self::bump_persistent(&env, &rel_key);
    }

    /// Configure vault release conditions
    pub fn configure_vault_release(
        env: Env,
        owner: Address,
        vault_id: u64,
        inactivity_period: u64,
    ) {
        owner.require_auth();
        Self::bump_instance(&env);

        let vault_key = DataKey::Vault(vault_id);
        let vault: Vault = env
            .storage()
            .persistent()
            .get(&vault_key)
            .expect("Vault not found");
        assert!(vault.creator == owner, "Only creator can configure release");
        assert!(vault.is_active, "Vault not active");
        assert!(
            (24 * 60 * 60..=365 * 24 * 60 * 60).contains(&inactivity_period),
            "Inactivity period must be between 1 and 365 days"
        );

        let rel_key = DataKey::ReleaseState(vault_id);
        let mut state: VaultReleaseState = env
            .storage()
            .persistent()
            .get(&rel_key)
            .unwrap();
        state.inactivity_period = inactivity_period;
        env.storage().persistent().set(&rel_key, &state);

        Self::bump_persistent(&env, &vault_key);
        Self::bump_persistent(&env, &rel_key);
    }

    /// Set vault emergency mode
    pub fn set_emergency_mode(env: Env, owner: Address, vault_id: u64, enabled: bool) {
        owner.require_auth();
        Self::bump_instance(&env);

        let vault_key = DataKey::Vault(vault_id);
        let vault: Vault = env
            .storage()
            .persistent()
            .get(&vault_key)
            .expect("Vault not found");
        assert!(vault.creator == owner, "Only creator can set emergency mode");
        assert!(vault.is_active, "Vault not active");

        let rel_key = DataKey::ReleaseState(vault_id);
        let mut state: VaultReleaseState = env
            .storage()
            .persistent()
            .get(&rel_key)
            .unwrap();
        state.emergency_mode = enabled;
        env.storage().persistent().set(&rel_key, &state);

        Self::bump_persistent(&env, &vault_key);
        Self::bump_persistent(&env, &rel_key);
    }

    /// Configure an optional external registry contract to be notified whenever
    /// a document access request on this vault is fully approved. The registry
    /// may be any Soroban contract (e.g. an audit log or a custom account's
    /// policy contract) - `Address` does not distinguish between a raw Stellar
    /// keypair account and a deployed contract address, so both are accepted.
    pub fn set_access_registry(env: Env, owner: Address, vault_id: u64, registry: Address) {
        owner.require_auth();
        Self::bump_instance(&env);

        let vault_key = DataKey::Vault(vault_id);
        let vault: Vault = env
            .storage()
            .persistent()
            .get(&vault_key)
            .expect("Vault not found");
        assert!(vault.creator == owner, "Only creator can set access registry");

        let registry_key = DataKey::AccessRegistry(vault_id);
        env.storage().persistent().set(&registry_key, &registry);
        Self::bump_persistent(&env, &registry_key);
    }

    /// Revoke a beneficiary's access to a document. Guardian-only, same-chain
    /// counterpart to the EVM contract's `revokeAccess`.
    pub fn revoke_access(env: Env, guardian: Address, document_id: u64, target: Address) {
        guardian.require_auth();
        Self::bump_instance(&env);

        let doc_key = DataKey::Doc(document_id);
        let doc: Document = env
            .storage()
            .persistent()
            .get(&doc_key)
            .expect("Document not found");

        let is_guard: bool = env
            .storage()
            .persistent()
            .get(&DataKey::IsGuardian(doc.vault_id, guardian))
            .unwrap_or(false);
        assert!(is_guard, "Only guardians can revoke access");

        Self::apply_revocation(&env, document_id, &target);
    }

    /// Link this Soroban vault to its EVM counterpart so cross-chain
    /// revocation broadcasts can be routed here: `vault_gid` is the globally
    /// unique id the EVM contract derives via `vaultGID(vaultId)`, and
    /// `evm_revoker` is the EVM address (typically an EVM-side guardian's
    /// EOA) authorized to sign revocation broadcasts for this vault.
    pub fn link_cross_chain_vault(
        env: Env,
        owner: Address,
        vault_id: u64,
        vault_gid: BytesN<32>,
        evm_revoker: BytesN<20>,
    ) {
        owner.require_auth();
        Self::bump_instance(&env);

        let vault_key = DataKey::Vault(vault_id);
        let vault: Vault = env
            .storage()
            .persistent()
            .get(&vault_key)
            .expect("Vault not found");
        assert!(vault.creator == owner, "Only creator can link cross-chain vault");

        let gid_key = DataKey::VaultGid(vault_gid);
        assert!(
            !env.storage().persistent().has(&gid_key),
            "vault_gid already linked to a vault"
        );
        env.storage().persistent().set(&gid_key, &vault_id);
        Self::bump_persistent(&env, &gid_key);

        let revoker_key = DataKey::CrossChainRevoker(vault_id);
        env.storage().persistent().set(&revoker_key, &evm_revoker);
        Self::bump_persistent(&env, &revoker_key);
    }

    /// Apply an EVM-originated access revocation broadcast to this vault's
    /// Soroban-side access grant, within the same Soroban ledger the call
    /// lands in - closing the window where a beneficiary revoked on EVM
    /// could still fetch document shares here.
    ///
    /// Trust model: the call is permissionless (anyone may relay it, like
    /// forwarding any signed message), but it only takes effect if
    /// `signature` recovers to the EVM address registered via
    /// `link_cross_chain_vault` as this vault's authorized cross-chain
    /// revoker. The signed digest commits to every argument below (including
    /// `target_stellar_user`, resolved off-chain before the EVM guardian
    /// signs), so a relayer cannot redirect a validly-signed message to a
    /// different beneficiary or vault. `nonce` must strictly increase per
    /// (vault_gid, document, beneficiary) triple, blocking replay - scoping
    /// by `vault_gid` rather than just document/beneficiary means that if the
    /// EVM contract is ever redeployed to a new address (and thus a new
    /// `vaultGID`, since it is derived from `address(this)`) and re-linked,
    /// nonce tracking starts fresh instead of being stuck behind whatever
    /// nonce the previous deployment last used.
    pub fn relay_revoke_access(
        env: Env,
        vault_gid: BytesN<32>,
        document_id: u64,
        target_evm_user: BytesN<20>,
        target_stellar_user: Address,
        nonce: u64,
        signature: BytesN<64>,
        recovery_id: u32,
    ) {
        Self::bump_instance(&env);

        let vault_id: u64 = env
            .storage()
            .persistent()
            .get(&DataKey::VaultGid(vault_gid.clone()))
            .expect("Unknown vault_gid");

        let doc_key = DataKey::Doc(document_id);
        let doc: Document = env
            .storage()
            .persistent()
            .get(&doc_key)
            .expect("Document not found");
        assert!(doc.vault_id == vault_id, "Document does not belong to linked vault");

        let nonce_key =
            DataKey::RevocationNonce(vault_gid.clone(), document_id, target_stellar_user.clone());
        let last_nonce: u64 = env.storage().persistent().get(&nonce_key).unwrap_or(0);
        assert!(nonce > last_nonce, "Stale or replayed revocation nonce");

        let revoker: BytesN<20> = env
            .storage()
            .persistent()
            .get(&DataKey::CrossChainRevoker(vault_id))
            .expect("No cross-chain revoker linked for this vault");

        let recovered = Self::recover_eth_address(
            &env,
            &vault_gid,
            document_id,
            &target_evm_user,
            &target_stellar_user,
            nonce,
            &signature,
            recovery_id,
        );
        assert!(recovered == revoker, "Signature not from linked cross-chain revoker");

        env.storage().persistent().set(&nonce_key, &nonce);
        Self::bump_persistent(&env, &nonce_key);

        Self::apply_revocation(&env, document_id, &target_stellar_user);
    }

    /// Helper function to check if release condition is satisfied
    pub fn is_release_condition_satisfied(
        env: &Env,
        vault_id: u64,
        condition: ReleaseCondition,
    ) -> bool {
        if condition == ReleaseCondition::Anytime {
            return true;
        }

        let rel_key = DataKey::ReleaseState(vault_id);
        let state: VaultReleaseState = env
            .storage()
            .persistent()
            .get(&rel_key)
            .expect("Vault state missing");
        Self::bump_persistent(env, &rel_key);

        let is_dead = env.ledger().timestamp() >= state.last_proof_of_life + state.inactivity_period;

        match condition {
            ReleaseCondition::LiveOnly => !is_dead,
            ReleaseCondition::EmergencyOnly => state.emergency_mode || is_dead,
            ReleaseCondition::PostDeathOnly => is_dead,
            ReleaseCondition::Anytime => true,
        }
    }

    pub fn get_vault(env: Env, vault_id: u64) -> Option<Vault> {
        Self::bump_instance(&env);
        let key = DataKey::Vault(vault_id);
        let vault: Option<Vault> = env.storage().persistent().get(&key);
        if vault.is_some() {
            Self::bump_persistent(&env, &key);
        }
        vault
    }

    pub fn get_document(env: Env, document_id: u64) -> Option<Document> {
        Self::bump_instance(&env);
        let key = DataKey::Doc(document_id);
        let doc: Option<Document> = env.storage().persistent().get(&key);
        if doc.is_some() {
            Self::bump_persistent(&env, &key);
        }
        doc
    }

    pub fn get_access_request(env: Env, request_id: u64) -> Option<AccessRequest> {
        Self::bump_instance(&env);
        let key = DataKey::Request(request_id);
        let req: Option<AccessRequest> = env.storage().persistent().get(&key);
        if req.is_some() {
            Self::bump_persistent(&env, &key);
        }
        req
    }

    pub fn get_invites(env: Env, guardian: Address) -> Vec<GuardianInvite> {
        Self::bump_instance(&env);
        let key = DataKey::Invites(guardian);
        let invites: Vec<GuardianInvite> = env
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or_else(|| Vec::new(&env));
        if env.storage().persistent().has(&key) {
            Self::bump_persistent(&env, &key);
        }
        invites
    }

    pub fn get_release_state(env: Env, vault_id: u64) -> Option<VaultReleaseState> {
        Self::bump_instance(&env);
        let key = DataKey::ReleaseState(vault_id);
        let state: Option<VaultReleaseState> = env.storage().persistent().get(&key);
        if state.is_some() {
            Self::bump_persistent(&env, &key);
        }
        state
    }

    /// Perform a deep, contract-authorized cross-contract call notifying an
    /// external registry that document access was granted.
    ///
    /// The vault contract itself - rather than the approving guardian - is the
    /// one invoking the registry, so the guardian's signature (verified above
    /// via `require_auth`) does not cover this sub-invocation. We use
    /// `env.authorize_as_current_contract` to have this contract authorize the
    /// call to `record_grant` "as itself" for exactly this invocation, which
    /// is required for the sub-invocation to pass the registry's own
    /// `require_auth` / custom-account `__check_auth` checks regardless of
    /// whether the registry is a plain account or a custom account
    /// abstraction (multisig / policy) contract.
    fn notify_access_registry(env: &Env, registry: &Address, document_id: u64, requester: &Address) {
        let fn_name = Symbol::new(env, "record_grant");
        let args: Vec<Val> = (document_id, requester.clone()).into_val(env);

        env.authorize_as_current_contract(soroban_sdk::vec![
            env,
            InvokerContractAuthEntry::Contract(SubContractInvocation {
                context: ContractContext {
                    contract: registry.clone(),
                    fn_name: fn_name.clone(),
                    args: args.clone(),
                },
                sub_invocations: Vec::new(env),
            }),
        ]);

        let _: Val = env.invoke_contract(registry, &fn_name, args);
    }

    /// Clear a beneficiary's access grant for a document. Shared by the
    /// guardian-initiated `revoke_access` and the cross-chain
    /// `relay_revoke_access` so both paths apply the exact same effect.
    fn apply_revocation(env: &Env, document_id: u64, target: &Address) {
        let acc_key = DataKey::HasAccess(document_id, target.clone());
        let lvl_key = DataKey::AccessLvl(document_id, target.clone());
        env.storage().persistent().set(&acc_key, &false);
        env.storage().persistent().remove(&lvl_key);
        Self::bump_persistent(env, &acc_key);

        env.events().publish(
            (Symbol::new(env, "access_revoked"), document_id),
            target.clone(),
        );
    }

    /// Recover the EVM (Ethereum-style) address that produced `signature`
    /// over the EIP-191-prefixed cross-chain revocation payload
    /// `("RevokeAccess", vault_gid, document_id, target_evm_user,
    /// target_stellar_user, nonce)`. `document_id` and `nonce` are packed as
    /// 32-byte big-endian words to match Solidity's `abi.encodePacked` of a
    /// `uint256`, and `target_stellar_user` is committed via its canonical
    /// XDR encoding.
    fn recover_eth_address(
        env: &Env,
        vault_gid: &BytesN<32>,
        document_id: u64,
        target_evm_user: &BytesN<20>,
        target_stellar_user: &Address,
        nonce: u64,
        signature: &BytesN<64>,
        recovery_id: u32,
    ) -> BytesN<20> {
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

        let pubkey = env.crypto().secp256k1_recover(&digest, signature, recovery_id);
        let pubkey_bytes: Bytes = pubkey.into();
        let addr_hash = env.crypto().keccak256(&pubkey_bytes.slice(1..65));
        let addr_bytes: Bytes = addr_hash.to_bytes().into();
        BytesN::try_from(addr_bytes.slice(12..32)).unwrap()
    }

    // Helper functions for TTL management
    fn bump_instance(env: &Env) {
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);
    }

    fn bump_persistent(env: &Env, key: &DataKey) {
        env.storage()
            .persistent()
            .extend_ttl(key, PERSISTENT_LIFETIME_THRESHOLD, PERSISTENT_BUMP_AMOUNT);
    }
}

#[cfg(test)]
mod test;
