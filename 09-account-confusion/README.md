# Account Confusion Vulnerabilities

## Overview

Account confusion occurs when programs fail to properly distinguish between different account types, allowing attackers to substitute accounts of the wrong type.

| # | Vulnerability | Severity | Description |
|---|--------------|----------|-------------|
| 01 | Type Confusion | Critical | Accepting wrong account type |
| 02 | Missing Discriminator | Critical | No type identifier in account data |
| 03 | Cross-Program Confusion | High | Accounts from different programs |

---

## Implementations

```
09-account-confusion/
├── README.md
├── anchor/
│   └── programs/
│       ├── confusion-vulnerable/
│       └── confusion-fixed/
└── pinocchio/
    └── programs/
        ├── type-confusion-vulnerable/
        └── type-confusion-fixed/
```

---

## The Vulnerability

### Memory Layout Problem

Different account types may have similar structures:

```
┌─────────────────────────────────────────────────────────────────┐
│                    ACCOUNT TYPE CONFUSION                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Vault Account Layout:              User Account Layout:        │
│  ┌──────────────────────┐           ┌──────────────────────┐   │
│  │ discriminator: 1     │           │ discriminator: 2     │   │
│  │ owner: Pubkey (32)   │           │ authority: Pubkey (32)│  │
│  │ balance: u64 (8)     │           │ points: u64 (8)      │   │
│  └──────────────────────┘           └──────────────────────┘   │
│        │                                   │                    │
│        │  Without discriminator check,     │                    │
│        │  bytes mean different things!     │                    │
│        └───────────────────────────────────┘                    │
│                                                                 │
│  Attacker passes User account to withdraw():                    │
│  - Program reads authority as "owner" (same offset)             │
│  - Program reads points as "balance" (same offset)              │
│  - Attacker controls their User account's values!               │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Anchor vs Pinocchio Comparison

### Anchor Implementation

Anchor uses 8-byte discriminators automatically:

```rust
// Anchor automatically adds 8-byte discriminator
#[account]
pub struct Vault {
    pub owner: Pubkey,
    pub balance: u64,
}

// Account validation checks discriminator automatically
#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,  // Must have Vault discriminator
}
```

**How Anchor Protects:**
- First 8 bytes are hash of `"account:Vault"`
- `Account<'info, Vault>` deserializes and checks discriminator
- Wrong type = transaction fails

### Pinocchio Implementation

Must implement discriminators manually:

```rust
// Vulnerable - no discriminator check
fn process_withdraw(accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    let [vault, authority] = accounts else { ... };

    let vault_data = unsafe { vault.borrow_data_unchecked() };
    
    // BUG: No discriminator check!
    // Any account with matching layout could be passed
    let stored_owner = &vault_data[0..32];  // Assumes Vault layout
    let balance = u64::from_le_bytes(vault_data[32..40].try_into().unwrap());
    
    // Attacker passes User account where authority = attacker
    // and points = huge number they set
}

// Fixed - explicit discriminator check
const VAULT_DISCRIMINATOR: u8 = 1;
const USER_DISCRIMINATOR: u8 = 2;

fn process_withdraw(accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    let [vault, authority] = accounts else { ... };

    let vault_data = unsafe { vault.borrow_data_unchecked() };
    
    // Check discriminator FIRST
    let discriminator = vault_data[0];
    if discriminator != VAULT_DISCRIMINATOR {
        msg!("Expected Vault, got discriminator {}", discriminator);
        return Err(ProgramError::InvalidAccountData);
    }
    
    // Now safe to interpret as Vault
    let stored_owner = &vault_data[1..33];  // Offset by 1 for discriminator
    let balance = u64::from_le_bytes(vault_data[33..41].try_into().unwrap());
    
    // Continue with verified Vault account
}
```

### Framework Comparison

| Aspect | Anchor | Pinocchio |
|--------|--------|-----------|
| Discriminator | Automatic 8-byte hash | Manual 1+ byte flag |
| Type checking | Compile-time via generics | Runtime explicit check |
| Account layout | `#[account]` macro | Manual byte offsets |
| Error on mismatch | Automatic deserialization error | Must return error explicitly |

---

## Memory Layout: Vulnerable vs Fixed

### Vulnerable (No Discriminator)

```
Vault: [owner: 32 bytes][balance: 8 bytes]
User:  [authority: 32 bytes][points: 8 bytes]
       ^
       Same structure - can be confused!
```

### Fixed (With Discriminator)

```
Vault: [discriminator: 1][owner: 32 bytes][balance: 8 bytes]
User:  [discriminator: 2][authority: 32 bytes][points: 8 bytes]
       ^
       Different first byte - easily distinguished
```

---

## Running Tests

```bash
cd anchor
anchor test
```

---

## References

- [Type Cosplay Attacks](https://github.com/coral-xyz/sealevel-attacks/tree/master/programs/3-type-cosplay)
- [Anchor Discriminators](https://book.anchor-lang.com/anchor_in_depth/discriminator.html)
