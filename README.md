# auria-license

License verification and management for AURIA Runtime Core.

## Overview

Validates shard access authorization through cryptographic license verification.

## License Structure

```rust
pub struct License {
    pub shard_id: ShardId,
    pub node_pubkey: PublicKey,
    pub expiry_timestamp: u64,
    pub signature: Signature,
}
```

## Usage

```rust
use auria_license::LicenseManager;

let mut manager = LicenseManager::new();
manager.register_license(license);
let is_valid = manager.validate_license(&license)?;
```
