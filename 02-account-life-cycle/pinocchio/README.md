# Pinocchio Implementation - Account Life Cycle

This directory contains the Pinocchio implementation of account lifecycle vulnerability examples.

## Structure

```
pinocchio/
├── Cargo.toml
├── README.md
└── programs/
    ├── reinitialization-vulnerable/    # No is_initialized check
    └── reinitialization-fixed/         # Uses is_initialized flag
```

## The Vulnerability: Reinitialization Attack

A reinitialization attack occurs when an attacker can call the initialization function on an already-initialized account and overwrite critical data like the owner field.

### Vulnerable Code

```rust
fn process_initialize(accounts: &[AccountInfo], value: u64) -> ProgramResult {
    let [config, payer, _system] = accounts else { ... };

    let config_data = unsafe { config.borrow_mut_data_unchecked() };

    // BUG: No check if account is already initialized!
    // Anyone can call this and overwrite the owner
    config_data[OWNER_OFFSET..OWNER_OFFSET + 32]
        .copy_from_slice(payer.key().as_ref());
    config_data[VALUE_OFFSET..VALUE_OFFSET + 8]
        .copy_from_slice(&value.to_le_bytes());

    Ok(())
}
```

### Attack Scenario

1. Alice initializes the config account with her pubkey as owner
2. Alice deposits funds into the program
3. Attacker calls `initialize` again
4. Attacker's pubkey overwrites Alice's owner field
5. Attacker calls `withdraw` and steals Alice's funds

### Fixed Code

```rust
// Memory layout now includes is_initialized flag
const IS_INITIALIZED_OFFSET: usize = 0;  // 1 byte
const OWNER_OFFSET: usize = 1;           // 32 bytes
const VALUE_OFFSET: usize = 33;          // 8 bytes

fn process_initialize(accounts: &[AccountInfo], value: u64) -> ProgramResult {
    let [config, payer, _system] = accounts else { ... };

    let config_data = unsafe { config.borrow_mut_data_unchecked() };

    // THE FIX: Check is_initialized flag
    let is_initialized = config_data[IS_INITIALIZED_OFFSET] != 0;

    if is_initialized {
        // Account exists - verify caller is the original owner
        let stored_owner = &config_data[OWNER_OFFSET..OWNER_OFFSET + 32];
        
        if stored_owner != payer.key().as_ref() {
            return Err(ProgramError::AccountAlreadyInitialized);
        }
        
        // Owner matches - only update value, NOT owner
        config_data[VALUE_OFFSET..VALUE_OFFSET + 8]
            .copy_from_slice(&value.to_le_bytes());
    } else {
        // First initialization - set all fields
        config_data[IS_INITIALIZED_OFFSET] = 1;
        config_data[OWNER_OFFSET..OWNER_OFFSET + 32]
            .copy_from_slice(payer.key().as_ref());
        config_data[VALUE_OFFSET..VALUE_OFFSET + 8]
            .copy_from_slice(&value.to_le_bytes());
    }

    Ok(())
}
```

## Anchor vs Pinocchio Comparison

### Anchor Approach

Anchor provides two patterns to prevent reinitialization:

**Pattern 1: Use `init` constraint**

```rust
#[account(
    init,  // Fails if account already exists
    payer = payer,
    space = 8 + Config::INIT_SPACE
)]
pub config: Account<'info, Config>,
```

**Pattern 2: Use `init_if_needed` with is_initialized check**

```rust
#[account(
    init_if_needed,
    payer = payer,
    space = 8 + Config::INIT_SPACE
)]
pub config: Account<'info, Config>,

// In instruction handler:
if config.is_initialized {
    require_keys_eq!(config.owner, payer.key(), Error::AlreadyInitialized);
}
```

### Pinocchio Approach

With Pinocchio, you must implement the check explicitly:

```rust
// Define is_initialized in your memory layout
const IS_INITIALIZED_OFFSET: usize = 0;

// Check before writing
let is_initialized = config_data[IS_INITIALIZED_OFFSET] != 0;
if is_initialized {
    // Reject or verify owner
    return Err(ProgramError::AccountAlreadyInitialized);
}

// Mark as initialized
config_data[IS_INITIALIZED_OFFSET] = 1;
```

## Memory Layout Comparison

### Vulnerable Layout (40 bytes)

```
Offset  Size  Field
------  ----  -----
0       32    owner (Pubkey)
32      8     value (u64 LE)
```

### Fixed Layout (41 bytes)

```
Offset  Size  Field
------  ----  -----
0       1     is_initialized (bool as u8)
1       32    owner (Pubkey)
33      8     value (u64 LE)
```

## Building

```bash
cargo build
cargo build-sbf --release  # For on-chain deployment
```

## Security Takeaways

1. Always track initialization state with a flag or discriminator
2. On reinitialization attempt: reject OR verify caller is original owner
3. Never allow owner field to be overwritten by non-owner
4. Consider using discriminators (like Anchor's 8-byte prefix) for type safety
5. The `init` pattern (fail if exists) is safer than `init_if_needed`
