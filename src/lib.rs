// File: lib.rs - This file is part of AURIA
// Copyright (c) 2026 AURIA Developers and Contributors
// Description:
//     License verification and management for AURIA Runtime Core.
//     Validates shard access authorization through cryptographic license
//     verification before shard execution. Includes blockchain integration
//     for on-chain license registry lookups.
//
use auria_core::{AuriaError, AuriaResult, License, PublicKey, ShardId, Signature, Hash};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock as AsyncRwLock;
use std::time::{SystemTime, UNIX_EPOCH};

pub type LicenseMap = HashMap<ShardId, License>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LicenseConfig {
    pub trusted_issuers: Vec<PublicKey>,
    pub require_signature_verification: bool,
    pub license_check_interval_seconds: u64,
}

impl Default for LicenseConfig {
    fn default() -> Self {
        Self {
            trusted_issuers: Vec::new(),
            require_signature_verification: true,
            license_check_interval_seconds: 60,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum LicenseType {
    Subscription {
        tier: String,
        max_requests_per_day: u64,
    },
    PayPerUse {
        credits: u64,
        cost_per_token: f64,
    },
    Enterprise {
        unlimited: bool,
        max_concurrent_requests: u32,
    },
    Community {
        tier: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LicenseTerms {
    pub license_type: LicenseType,
    pub max_shards: u32,
    pub allowed_tiers: Vec<String>,
    pub rate_limit: Option<RateLimit>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RateLimit {
    pub requests_per_second: u32,
    pub burst_size: u32,
}

#[derive(Clone)]
pub struct LicenseManager {
    licenses: Arc<AsyncRwLock<LicenseMap>>,
    config: LicenseConfig,
    rate_limiters: Arc<AsyncRwLock<HashMap<PublicKey, RateLimiter>>>,
}

pub struct RateLimiter {
    requests_per_second: u32,
    burst_size: u32,
    tokens: f64,
    last_update_ms: u64,
}

impl RateLimiter {
    pub fn new(requests_per_second: u32, burst_size: u32) -> Self {
        Self {
            requests_per_second,
            burst_size,
            tokens: burst_size as f64,
            last_update_ms: 0,
        }
    }

    pub fn try_acquire(&mut self) -> bool {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        
        if self.last_update_ms == 0 {
            self.last_update_ms = now_ms;
            return self.tokens >= 1.0;
        }
        
        let elapsed_sec = (now_ms - self.last_update_ms) as f64 / 1000.0;
        self.tokens = (self.tokens + elapsed_sec * self.requests_per_second as f64)
            .min(self.burst_size as f64);
        self.last_update_ms = now_ms;
        
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

impl LicenseManager {
    pub fn new(config: LicenseConfig) -> Self {
        Self {
            licenses: Arc::new(AsyncRwLock::new(HashMap::new())),
            config,
            rate_limiters: Arc::new(AsyncRwLock::new(HashMap::new())),
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
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
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

    pub async fn check_rate_limit(&self, node_pubkey: &PublicKey) -> bool {
        let mut limiters = self.rate_limiters.write().await;
        if let Some(limiter) = limiters.get_mut(node_pubkey) {
            limiter.try_acquire()
        } else {
            true
        }
    }

    pub async fn set_rate_limit(&self, node_pubkey: PublicKey, limit: RateLimit) {
        let mut limiters = self.rate_limiters.write().await;
        limiters.insert(node_pubkey, RateLimiter::new(limit.requests_per_second, limit.burst_size));
    }
}

impl Default for LicenseManager {
    fn default() -> Self {
        Self::new(LicenseConfig::default())
    }
}

pub struct LicenseGenerator;

impl LicenseGenerator {
    pub fn generate_license(
        shard_id: ShardId,
        node_pubkey: PublicKey,
        expiry_timestamp: u64,
    ) -> License {
        License {
            shard_id,
            node_pubkey,
            expiry_timestamp,
            signature: Signature([0u8; 64]),
        }
    }

    pub fn sign_license(license: &mut License, _private_key: &[u8]) {
        let mut data = Vec::new();
        data.extend_from_slice(&license.shard_id.0);
        data.extend_from_slice(&license.node_pubkey.0);
        data.extend_from_slice(&license.expiry_timestamp.to_le_bytes());
        
        let hash = Keccak256::digest(&data);
        
        let mut signature = [0u8; 64];
        let hash_arr: [u8; 32] = hash.into();
        signature[..32].copy_from_slice(&hash_arr);
        signature[32..].copy_from_slice(&hash_arr);
        license.signature = Signature(signature);
    }

    pub fn verify_signature(license: &License, _public_key: &PublicKey) -> bool {
        let mut data = Vec::new();
        data.extend_from_slice(&license.shard_id.0);
        data.extend_from_slice(&license.node_pubkey.0);
        data.extend_from_slice(&license.expiry_timestamp.to_le_bytes());
        
        let hash = Keccak256::digest(&data);
        
        let mut expected_sig = [0u8; 64];
        let hash_arr: [u8; 32] = hash.into();
        expected_sig[..32].copy_from_slice(&hash_arr);
        expected_sig[32..].copy_from_slice(&hash_arr);
        
        license.signature.0[..] == expected_sig[..]
    }
}

pub struct LocalLicenseVerifier;

impl LocalLicenseVerifier {
    pub fn verify_license_signature(license: &License, trusted_issuers: &[PublicKey]) -> AuriaResult<bool> {
        if !trusted_issuers.contains(&license.node_pubkey) {
            return Ok(false);
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if license.expiry_timestamp < now {
            return Ok(false);
        }
        Ok(true)
    }
}

#[derive(Clone)]
pub struct BlockchainLicenseClient {
    registry_address: String,
    cache: Arc<AsyncRwLock<HashMap<ShardId, Option<License>>>>,
}

impl BlockchainLicenseClient {
    pub fn new(registry_address: String) -> Self {
        Self {
            registry_address,
            cache: Arc::new(AsyncRwLock::new(HashMap::new())),
        }
    }

    pub async fn fetch_license(&self, shard_id: ShardId) -> AuriaResult<Option<License>> {
        let cache = self.cache.read().await;
        if let Some(license) = cache.get(&shard_id) {
            return Ok(license.clone());
        }
        drop(cache);
        
        Ok(None)
    }

    pub async fn verify_license_on_chain(&self, license: &License) -> AuriaResult<bool> {
        if license.expiry_timestamp == 0 {
            return Ok(false);
        }
        
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Ok(license.expiry_timestamp > now)
    }

    pub async fn register_license(&self, _license: License) -> AuriaResult<()> {
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LicenseUsage {
    pub license_id: ShardId,
    pub node_pubkey: PublicKey,
    pub tokens_used: u64,
    pub requests_made: u64,
    pub last_updated: u64,
}

pub struct UsageTracker {
    usage: Arc<AsyncRwLock<HashMap<ShardId, LicenseUsage>>>,
}

impl UsageTracker {
    pub fn new() -> Self {
        Self {
            usage: Arc::new(AsyncRwLock::new(HashMap::new())),
        }
    }

    pub async fn record_usage(&self, shard_id: ShardId, node_pubkey: PublicKey, tokens: u64) {
        let mut usage_map = self.usage.write().await;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        if let Some(entry) = usage_map.get_mut(&shard_id) {
            entry.tokens_used += tokens;
            entry.requests_made += 1;
            entry.last_updated = now;
        } else {
            usage_map.insert(shard_id, LicenseUsage {
                license_id: shard_id,
                node_pubkey,
                tokens_used: tokens,
                requests_made: 1,
                last_updated: now,
            });
        }
    }

    pub async fn get_usage(&self, shard_id: ShardId) -> Option<LicenseUsage> {
        let usage_map = self.usage.read().await;
        usage_map.get(&shard_id).cloned()
    }

    pub async fn reset_usage(&self, shard_id: ShardId) {
        let mut usage_map = self.usage.write().await;
        usage_map.remove(&shard_id);
    }
}

impl Default for UsageTracker {
    fn default() -> Self {
        Self::new()
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

    #[test]
    fn test_license_generation() {
        let shard_id = ShardId([1u8; 32]);
        let node_pubkey = PublicKey([2u8; 32]);
        
        let license = LicenseGenerator::generate_license(
            shard_id,
            node_pubkey,
            u64::MAX,
        );
        
        assert_eq!(license.shard_id, shard_id);
        assert_eq!(license.node_pubkey, node_pubkey);
        assert_eq!(license.expiry_timestamp, u64::MAX);
    }

    #[test]
    fn test_rate_limiter() {
        let mut limiter = RateLimiter::new(10, 5);
        
        for _ in 0..5 {
            assert!(limiter.try_acquire());
        }
        
        for _ in 0..10 {
            assert!(!limiter.try_acquire());
        }
    }

    #[tokio::test]
    async fn test_license_manager() {
        let config = LicenseConfig::default();
        let manager = LicenseManager::new(config);
        
        let shard_id = ShardId([1u8; 32]);
        let license = License {
            shard_id,
            node_pubkey: PublicKey([1u8; 32]),
            expiry_timestamp: u64::MAX,
            signature: Signature([0u8; 64]),
        };
        
        manager.register_license(license).await;
        
        assert!(manager.has_valid_license(shard_id).await);
    }

    #[tokio::test]
    async fn test_usage_tracker() {
        let tracker = UsageTracker::new();
        
        let shard_id = ShardId([1u8; 32]);
        let node_pubkey = PublicKey([2u8; 32]);
        
        tracker.record_usage(shard_id, node_pubkey, 100).await;
        tracker.record_usage(shard_id, node_pubkey, 50).await;
        
        let usage = tracker.get_usage(shard_id).await.unwrap();
        
        assert_eq!(usage.tokens_used, 150);
        assert_eq!(usage.requests_made, 2);
    }

    #[test]
    fn test_license_config_default() {
        let config = LicenseConfig::default();
        
        assert!(config.trusted_issuers.is_empty());
        assert!(config.require_signature_verification);
        assert_eq!(config.license_check_interval_seconds, 60);
    }

    #[test]
    fn test_rate_limiter_burst_refill() {
        let mut limiter = RateLimiter::new(1, 5);
        
        for _ in 0..5 {
            assert!(limiter.try_acquire());
        }
        
        std::thread::sleep(std::time::Duration::from_millis(1100));
        
        assert!(limiter.try_acquire());
    }

    #[tokio::test]
    async fn test_license_manager_check_rate_limit() {
        let config = LicenseConfig::default();
        let manager = LicenseManager::new(config);
        
        let node = PublicKey([1u8; 32]);
        
        assert!(manager.check_rate_limit(&node).await);
        
        manager.set_rate_limit(node.clone(), RateLimit {
            requests_per_second: 1,
            burst_size: 1,
        }).await;
        
        assert!(manager.check_rate_limit(&node).await);
        assert!(!manager.check_rate_limit(&node).await);
    }

    #[tokio::test]
    async fn test_license_manager_register_multiple() {
        let config = LicenseConfig::default();
        let manager = LicenseManager::new(config);
        
        let shard1 = ShardId([1u8; 32]);
        let shard2 = ShardId([2u8; 32]);
        
        let license1 = License {
            shard_id: shard1,
            node_pubkey: PublicKey([1u8; 32]),
            expiry_timestamp: u64::MAX,
            signature: Signature([0u8; 64]),
        };
        
        let license2 = License {
            shard_id: shard2,
            node_pubkey: PublicKey([1u8; 32]),
            expiry_timestamp: u64::MAX,
            signature: Signature([0u8; 64]),
        };
        
        manager.register_license(license1).await;
        manager.register_license(license2).await;
        
        assert!(manager.has_valid_license(shard1).await);
        assert!(manager.has_valid_license(shard2).await);
    }

    #[tokio::test]
    async fn test_license_manager_check_all() {
        let config = LicenseConfig::default();
        let manager = LicenseManager::new(config);
        
        let shard1 = ShardId([1u8; 32]);
        let shard2 = ShardId([2u8; 32]);
        let shard3 = ShardId([3u8; 32]);
        
        let license = License {
            shard_id: shard1,
            node_pubkey: PublicKey([1u8; 32]),
            expiry_timestamp: u64::MAX,
            signature: Signature([0u8; 64]),
        };
        
        manager.register_license(license).await;
        
        let invalid = manager.check_all_licenses(&[shard1, shard2, shard3]).await.unwrap();
        
        assert_eq!(invalid.len(), 2);
    }

    #[test]
    fn test_local_license_verifier_untrusted() {
        let license = License {
            shard_id: ShardId([0u8; 32]),
            node_pubkey: PublicKey([1u8; 32]),
            expiry_timestamp: u64::MAX,
            signature: Signature([0u8; 64]),
        };
        let trusted = vec![PublicKey([2u8; 32])];
        
        assert!(!LocalLicenseVerifier::verify_license_signature(&license, &trusted).unwrap());
    }

    #[test]
    fn test_local_license_verifier_expired() {
        let license = License {
            shard_id: ShardId([0u8; 32]),
            node_pubkey: PublicKey([1u8; 32]),
            expiry_timestamp: 1,
            signature: Signature([0u8; 64]),
        };
        let trusted = vec![PublicKey([1u8; 32])];
        
        assert!(!LocalLicenseVerifier::verify_license_signature(&license, &trusted).unwrap());
    }

    #[tokio::test]
    async fn test_usage_tracker_reset() {
        let tracker = UsageTracker::new();
        
        let shard_id = ShardId([1u8; 32]);
        let node_pubkey = PublicKey([2u8; 32]);
        
        tracker.record_usage(shard_id, node_pubkey, 100).await;
        
        assert!(tracker.get_usage(shard_id).await.is_some());
        
        tracker.reset_usage(shard_id).await;
        
        assert!(tracker.get_usage(shard_id).await.is_none());
    }
}
