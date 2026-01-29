# Account Lifecycle Vulnerabilities

## Overview

Account lifecycle bugs occur when programs mishandle account creation, 
modification, or destruction. These bugs can lead to account takeover or 
double-spend scenarios.

| # | Vulnerability | Severity | Description |
|---|--------------|----------|-------------|
| 01 | Reinitialization | Critical | Account re-initialized, owner overwritten |
| 02 | Account Resurrection | High | Closed account revived with old data |

---

## Implementations

This module includes both Anchor and Pinocchio implementations.

```
02-account-life-cycle/
├── README.md
├── anchor/                    # Anchor framework implementation
│   └── programs/
│       ├── 01-reinitialization-vulnerable/
│       ├── 01-reinitialization-fixed/
│       ├── 02-account-resurrection-vulnerable/
│       └── 02-account-resurrection-fixed/
└── pinocchio/                 # Pinocchio framework implementation
    └── programs/
        ├── reinitialization-vulnerable/
        └── reinitialization-fixed/
```

---

## Solana Account Lifecycle

```
Created -> Active -> Closed
   |         |          |
   |         |          +-- lamports = 0, data zeroed, owner = System
   |         +------------- lamports > 0, data valid, owner = program
   +----------------------- init allocates space, sets owner
```

Key points:
- An account is "closed" when lamports = 0 at transaction end
- Runtime garbage collects zero-lamport accounts
- If lamports are refunded before tx ends, account persists

---

## 01 - Reinitialization

### The Bug

A reinitialization attack occurs when an attacker can call the initialization function on an already-initialized account and overwrite critical data like the owner field.

### Attack Scenario

1. Alice initializes the config account with her pubkey as owner
2. Alice deposits funds into the program
3. Attacker calls `initialize` again on the same account
4. Attacker's pubkey overwrites Alice's owner field
5. Attacker calls `withdraw` and steals Alice's funds

---

## Anchor vs Pinocchio Comparison

### Anchor Implementation

**Vulnerable - init_if_needed without checking state:**

```rust
#[derive(Accounts)]
pub struct InitializeOrUpdate<'info> {
    #[account(
        init_if_needed,  // Does NOT fail if account exists
        payer = payer,
        space = 8 + Config::INIT_SPACE,
        seeds = [b"config"],
        bump
    )]
    pub config: Account<'info, Config>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

pub fn initialize_or_update(ctx: Context<InitializeOrUpdate>, value: u64) -> Result<()> {
    let config = &mut ctx.accounts.config;
    
    // BUG: Always overwrites owner, even if account exists!
    config.owner = ctx.accounts.payer.key();
    config.value = value;
    Ok(())
}
```

**Fixed - Option 1: Use `init` constraint:**

```rust
#[account(
    init,  // Fails if account already exists
    payer = payer,
    space = 8 + Config::INIT_SPACE,
    seeds = [b"config"],
    bump
)]
pub config: Account<'info, Config>,
```

**Fixed - Option 2: Check is_initialized flag:**

```rust
pub fn initialize_safe(ctx: Context<InitializeSafe>, value: u64) -> Result<()> {
    let config = &mut ctx.accounts.config;
    
    if config.is_initialized {
        // Account exists - verify caller is original owner
        require_keys_eq!(
            config.owner, 
            ctx.accounts.payer.key(), 
            ConfigError::AlreadyInitialized
        );
        // Only update value, not owner
        config.value = value;
    } else {
        // First initialization
        config.owner = ctx.accounts.payer.key();
        config.value = value;
        config.is_initialized = true;
    }
    Ok(())
}
```

### Pinocchio Implementation

**Vulnerable - No is_initialized check:**

```rust
// Memory layout (40 bytes)
const OWNER_OFFSET: usize = 0;   // 32 bytes
const VALUE_OFFSET: usize = 32;  // 8 bytes

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

**Fixed - Uses is_initialized flag:**

```rust
// Memory layout (41 bytes) - added is_initialized flag
const IS_INITIALIZED_OFFSET: usize = 0;  // 1 byte
const OWNER_OFFSET: usize = 1;           // 32 bytes
const VALUE_OFFSET: usize = 33;          // 8 bytes

fn process_initialize(accounts: &[AccountInfo], value: u64) -> ProgramResult {
    let [config, payer, _system] = accounts else { ... };

    let config_data = unsafe { config.borrow_mut_data_unchecked() };

    // THE FIX: Check is_initialized flag
    let is_initialized = config_data[IS_INITIALIZED_OFFSET] != 0;

    if is_initialized {
        // Account exists - verify caller is original owner
        let stored_owner = &config_data[OWNER_OFFSET..OWNER_OFFSET + 32];
        
        if stored_owner != payer.key().as_ref() {
            return Err(ProgramError::AccountAlreadyInitialized);
        }
        
        // Owner matches - only update value, NOT owner
        config_data[VALUE_OFFSET..VALUE_OFFSET + 8]
            .copy_from_slice(&value.to_le_bytes());
    } else {
        // First initialization - set all fields
        config_data[IS_INITIALIZED_OFFSET] = 1;  // Mark initialized
        config_data[OWNER_OFFSET..OWNER_OFFSET + 32]
            .copy_from_slice(payer.key().as_ref());
        config_data[VALUE_OFFSET..VALUE_OFFSET + 8]
            .copy_from_slice(&value.to_le_bytes());
    }

    Ok(())
}
```

---

## Framework Comparison Table

| Aspect | Anchor | Pinocchio |
|--------|--------|-----------|
| **Init protection** | `init` constraint fails if exists | Must check is_initialized byte manually |
| **Init if needed** | `init_if_needed` + manual check | Same pattern but all manual |
| **State tracking** | Can use struct field | Must reserve byte in layout |
| **Discriminator** | Automatic 8-byte prefix | Must implement yourself |
| **Close account** | `close = dest` zeros + drains | Manual zero + drain lamports |

### Security Trade-offs

| Framework | Advantages | Disadvantages |
|-----------|------------|---------------|
| **Anchor** | `init` automatically prevents reinit; Discriminator provides type safety | `init_if_needed` still requires careful handling |
| **Pinocchio** | Full visibility into checks; Control over memory layout | Must remember to add is_initialized flag; Easy to forget |

---

## 02 - Account Resurrection

### The Bug

```rust
// VULNERABLE - only drains lamports, doesn't zero data
let escrow_lamports = escrow.lamports();
**escrow.try_borrow_mut_lamports()? = 0;
**owner.try_borrow_mut_lamports()? += escrow_lamports;
// BUG: Data still intact! If refunded, account resurrects
```

### Why It Happens

1. Lamports drained to 0
2. If another instruction refunds lamports in same tx, account persists
3. Account data (including claimed=false) remains intact
4. Attacker can claim again

### The Fix

**Anchor - Use close constraint:**

```rust
#[account(mut, close = owner)]
pub escrow: Account<'info, Escrow>,
```

Anchor automatically zeros data and sets discriminator.

**Pinocchio - Manual zeroing:**

```rust
let config_data = unsafe { config.borrow_mut_data_unchecked() };

// Zero all data first
for byte in config_data.iter_mut() {
    *byte = 0;
}

// Then drain lamports
unsafe {
    *config.borrow_mut_lamports_unchecked() = 0;
}
```

---

## Key Anchor Constraints

| Constraint | Behavior |
|------------|----------|
| `init` | Create new account, fail if exists |
| `init_if_needed` | Create if missing, continue if exists |
| `close = dest` | Zero data, drain lamports to dest |
| `realloc` | Resize account data |

---

## Running the Examples

### Anchor

```bash
cd anchor
yarn install
anchor test
```

### Pinocchio

```bash
cd pinocchio
cargo build
cargo build-sbf --release
```

---

## References

- Anchor close constraint: https://www.anchor-lang.com/docs/account-constraints
- Solana account model: https://docs.solana.com/developing/programming-model/accounts
- Pinocchio: https://github.com/febo/pinocchio