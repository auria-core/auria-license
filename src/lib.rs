use auria_core::{AuriaError, AuriaResult, License, ShardId};

pub struct LicenseManager {
    licenses: std::collections::HashMap<ShardId, License>,
}

impl LicenseManager {
    pub fn new() -> Self {
        Self {
            licenses: std::collections::HashMap::new(),
        }
    }

    pub fn validate_license(&self, license: &License) -> AuriaResult<bool> {
        let stored = self.licenses.get(&license.shard_id);
        match stored {
            Some(stored_license) => {
                if stored_license.node_pubkey != license.node_pubkey {
                    return Ok(false);
                }
                if stored_license.expiry_timestamp
                    < std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs()
                {
                    return Ok(false);
                }
                Ok(true)
            }
            None => Err(AuriaError::LicenseInvalid(license.shard_id)),
        }
    }

    pub fn license_valid_for_shard(&self, shard_id: ShardId) -> bool {
        if let Some(license) = self.licenses.get(&shard_id) {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            license.expiry_timestamp > now
        } else {
            false
        }
    }

    pub fn register_license(&mut self, license: License) {
        self.licenses.insert(license.shard_id, license);
    }
}
