# Pinocchio Implementation - Access Control

This directory contains the Pinocchio (zero-copy, lightweight) implementation of the access control vulnerability examples.

## What is Pinocchio?

Pinocchio is a zero-copy Solana program framework that provides:
- Zero-copy account deserialization
- Minimal runtime overhead  
- Direct memory access patterns
- No macro magic - explicit control flow

## Structure

```
pinocchio/
├── Cargo.toml
├── README.md
└── programs/
    ├── missing-signer-vulnerable/    # Vulnerable: no is_signer() check
    │   ├── Cargo.toml
    │   └── src/lib.rs
    └── missing-signer-fixed/         # Fixed: proper is_signer() verification
        ├── Cargo.toml
        └── src/lib.rs
```

## The Vulnerability

### Vulnerable Code (missing-signer-vulnerable)

```rust
fn process_withdraw(accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    let [vault, authority] = accounts else { ... };

    // Check authority matches vault.authority
    let stored_authority = &vault_data[AUTHORITY_OFFSET..AUTHORITY_OFFSET + 32];
    if stored_authority != authority.key().as_ref() {
        return Err(ProgramError::InvalidAccountData);
    }

    // BUG: Missing this check!
    // Anyone can pass the correct pubkey without proving they own it
    // if !authority.is_signer() {
    //     return Err(ProgramError::MissingRequiredSignature);
    // }

    // Withdraw proceeds without signature verification...
    unsafe {
        *vault.borrow_mut_lamports_unchecked() -= amount;
        *authority.borrow_mut_lamports_unchecked() += amount;
    }
}
```

### Fixed Code (missing-signer-fixed)

```rust
fn process_withdraw(accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    let [vault, authority] = accounts else { ... };

    // THE FIX: Verify authority signed the transaction
    if !authority.is_signer() {
        msg!("Authority must sign the transaction");
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Verify authority matches vault.authority
    let stored_authority = &vault_data[AUTHORITY_OFFSET..AUTHORITY_OFFSET + 32];
    if stored_authority != authority.key().as_ref() {
        return Err(ProgramError::InvalidAccountData);
    }

    // Now safe to withdraw - authority proved ownership via signature
    unsafe {
        *vault.borrow_mut_lamports_unchecked() -= amount;
        *authority.borrow_mut_lamports_unchecked() += amount;
    }
}
```

## Key Difference from Anchor

In Anchor, the `Signer<'info>` type handles the check automatically:

```rust
// Anchor - implicit check via type system
#[derive(Accounts)]
pub struct Withdraw<'info> {
    pub authority: Signer<'info>,  // Anchor verifies is_signer automatically
}
```

In Pinocchio, you must explicitly check:

```rust
// Pinocchio - explicit check required
if !authority.is_signer() {
    return Err(ProgramError::MissingRequiredSignature);
}
```

This explicit approach gives you more control but requires discipline to add the checks everywhere they are needed.

## Building

Build for native testing:

```bash
cargo build
```

Build for Solana BPF target:

```bash
cargo build-sbf --release
```

## Memory Layout

The vault account has a simple 40-byte layout:

```
Offset  Size  Field
------  ----  -----
0       32    authority (Pubkey)
32      8     balance (u64 little-endian)
```

Accessed via direct byte slicing:

```rust
const AUTHORITY_OFFSET: usize = 0;
const BALANCE_OFFSET: usize = 32;

let vault_data = unsafe { vault.borrow_mut_data_unchecked() };

// Read authority pubkey
let authority = &vault_data[AUTHORITY_OFFSET..AUTHORITY_OFFSET + 32];

// Read balance as u64
let balance = u64::from_le_bytes(
    vault_data[BALANCE_OFFSET..BALANCE_OFFSET + 8].try_into().unwrap()
);

// Write new balance
vault_data[BALANCE_OFFSET..BALANCE_OFFSET + 8].copy_from_slice(&new_balance.to_le_bytes());
```

## Instruction Format

Instructions use a simple discriminator + data format:

| Byte | Content |
|------|---------|
| 0 | Discriminator (0=init, 1=deposit, 2=withdraw) |
| 1-8 | Amount (u64 little-endian) for deposit/withdraw |

Example instruction data for depositing 1000 lamports:

```
[0x01, 0xE8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
 │     └────────────────────────────────────────────┘
 │                    1000 as u64 LE
 └── DEPOSIT discriminator
```

## Security Takeaways

1. Always verify `is_signer()` for privileged operations
2. Checking pubkey match alone is NOT sufficient
3. The Solana runtime sets `is_signer` based on transaction signatures
4. Without signature verification, anyone can claim to be any authority
