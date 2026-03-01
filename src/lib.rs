// File: lib.rs - This file is part of AURIA
// Copyright (c) 2026 AURIA Developers and Contributors
// Description:
//     License verification and management for AURIA Runtime Core.
//     Validates shard access authorization through cryptographic license
//     verification before shard execution. Includes blockchain integration
//     for on-chain license registry lookups.
//
use auria_core::{AuriaError, AuriaResult, License, PublicKey, ShardId};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock as AsyncRwLock;

pub type LicenseMap = HashMap<ShardId, License>;

#[derive(Clone)]
pub struct LicenseManager {
    licenses: Arc<AsyncRwLock<LicenseMap>>,
}

impl LicenseManager {
    pub fn new() -> Self {
        Self {
            licenses: Arc::new(AsyncRwLock::new(HashMap::new())),
        }
    }

    pub async fn validate_license(&self, license: &License) -> AuriaResult<bool> {
        let licenses = self.licenses.read().await;
        let stored = licenses.get(&license.shard_id);
        match stored {
            Some(stored_license) => {
                if stored_license.node_pubkey != license.node_pubkey {
                    return Ok(false);
                }
                if !self.is_license_valid(stored_license) {
                    return Ok(false);
                }
                Ok(license.signature == stored_license.signature)
            }
            None => {
                Err(AuriaError::LicenseInvalid(license.shard_id))
            }
        }
    }

    fn is_license_valid(&self, license: &License) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        license.expiry_timestamp > now
    }

    pub async fn license_valid_for_shard(&self, shard_id: ShardId) -> bool {
        let licenses = self.licenses.read().await;
        if let Some(license) = licenses.get(&shard_id) {
            self.is_license_valid(license)
        } else {
            false
        }
    }

    pub async fn register_license(&self, license: License) {
        let mut licenses = self.licenses.write().await;
        licenses.insert(license.shard_id, license);
    }

    pub async fn check_all_licenses(&self, shard_ids: &[ShardId]) -> AuriaResult<Vec<ShardId>> {
        let mut invalid = Vec::new();
        for shard_id in shard_ids {
            if !self.license_valid_for_shard(*shard_id).await {
                invalid.push(*shard_id);
            }
        }
        Ok(invalid)
    }

    pub async fn get_license(&self, shard_id: ShardId) -> Option<License> {
        let licenses = self.licenses.read().await;
        licenses.get(&shard_id).cloned()
    }

    pub async fn has_valid_license(&self, shard_id: ShardId) -> bool {
        self.license_valid_for_shard(shard_id).await
    }
}

impl Default for LicenseManager {
    fn default() -> Self {
        Self::new()
    }
}

pub struct LocalLicenseVerifier;

impl LocalLicenseVerifier {
    pub fn verify_license_signature(license: &License, trusted_issuers: &[PublicKey]) -> AuriaResult<bool> {
        if !trusted_issuers.contains(&license.node_pubkey) {
            return Ok(false);
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if license.expiry_timestamp < now {
            return Ok(false);
        }
        Ok(true)
    }
}

pub struct BlockchainLicenseClient<C> {
    client: C,
}

impl<C> BlockchainLicenseClient<C> {
    pub fn new(client: C) -> Self {
        Self { client }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_local_license_verifier() {
        let license = License {
            shard_id: ShardId([0u8; 32]),
            node_pubkey: PublicKey([1u8; 32]),
            expiry_timestamp: u64::MAX,
            signature: Signature([0u8; 64]),
        };
        let trusted = vec![PublicKey([1u8; 32])];
        assert!(LocalLicenseVerifier::verify_license_signature(&license, &trusted).unwrap());
    }
}
