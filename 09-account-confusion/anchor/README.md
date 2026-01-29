# 09 - Account Confusion Vulnerability ($50M Bug Class)

This module covers one of the most critical and costly vulnerability classes in Solana: **Account Type Confusion**. This bug class has been responsible for exploits totaling over $50 million, including the infamous $52M Cashio hack.

---

## Overview

| Vulnerability | Risk Level | Impact | Real-World Loss |
|---------------|------------|--------|-----------------|
| Account Type Confusion | Critical | Complete fund drainage | $52M (Cashio) |
| Discriminator Bypass | Critical | Authority hijacking | Multiple exploits |
| Cross-Account Data Overlap | High | Privilege escalation | Various protocols |

---

## What is Account Confusion?

Account confusion (also called type confusion) occurs when a Solana program fails to validate that an account is of the expected type before deserializing and using its data.

Solana stores all data as raw bytes. When different account types have **overlapping memory layouts**, an attacker can craft a malicious account that, when deserialized as a different type, gives them unauthorized access.

---

## The $50M Bug Pattern

### Memory Layout Overlap

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│           ACCOUNT TYPE CONFUSION - MEMORY LAYOUT ATTACK                        │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  LEGITIMATE POOL ACCOUNT:                                                       │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │ Offset │ Size │ Field            │ Value                               │    │
│  ├────────┼──────┼──────────────────┼─────────────────────────────────────┤    │
│  │ 0-8    │ 8    │ Discriminator    │ 0xABCD... (Pool type)               │    │
│  │ 8-40   │ 32   │ authority        │ ADMIN_PUBKEY                        │    │
│  │ 40-48  │ 8    │ total_liquidity  │ 5,000,000,000 (5 SOL)               │    │
│  │ 48-49  │ 1    │ is_active        │ 0x01 (true)                         │    │
│  └─────────────────────────────────────────────────────────────────────────┘    │
│                                                                                 │
│  ATTACKER'S USER VAULT (crafted to exploit):                                    │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │ Offset │ Size │ Field            │ Value                               │    │
│  ├────────┼──────┼──────────────────┼─────────────────────────────────────┤    │
│  │ 0-8    │ 8    │ Discriminator    │ 0xEFGH... (UserVault type)          │    │
│  │ 8-40   │ 32   │ owner            │ ATTACKER_PUBKEY  <-- Same offset!   │    │
│  │ 40-48  │ 8    │ deposited_amount │ 100,000,000 (0.1 SOL)               │    │
│  │ 48-49  │ 1    │ is_initialized   │ 0x01 (true)                         │    │
│  └─────────────────────────────────────────────────────────────────────────┘    │
│                                                                                 │
│  WHEN PROGRAM READS USER VAULT AS POOL:                                         │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │ Field             │ Actually Read         │ Interpreted As             │    │
│  ├───────────────────┼───────────────────────┼────────────────────────────┤    │
│  │ Discriminator     │ 0xEFGH... (UserVault) │ Skipped (vulnerability!)   │    │
│  │ authority         │ ATTACKER_PUBKEY       │ Pool admin = ATTACKER!     │    │
│  │ total_liquidity   │ 0.1 SOL               │ Withdrawable amount        │    │
│  │ is_active         │ true                  │ Pool is active             │    │
│  └─────────────────────────────────────────────────────────────────────────┘    │
│                                                                                 │
│  RESULT: Attacker gains admin privileges over their fake "pool"!               │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Attack Flow

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                      ACCOUNT CONFUSION EXPLOIT FLOW                             │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  1. SETUP: Protocol has Pool and UserVault with similar layouts                │
│     ┌───────────────────────────────────────────────────────────────────┐       │
│     │  Pool:      [discr][authority: 32][liquidity: 8][active: 1]      │       │
│     │  UserVault: [discr][owner: 32    ][deposited: 8][init: 1  ]      │       │
│     │             ↑       ↑              ↑             ↑               │       │
│     │             Fields at same offsets after discriminator!          │       │
│     └───────────────────────────────────────────────────────────────────┘       │
│                                            │                                    │
│                                            ▼                                    │
│  2. ATTACKER: Creates UserVault with their pubkey as "owner"                    │
│     ┌───────────────────────────────────────────────────────────────────┐       │
│     │  UserVault.owner = ATTACKER_PUBKEY                                │       │
│     │  This is at offset 8-40, same as Pool.authority!                  │       │
│     └───────────────────────────────────────────────────────────────────┘       │
│                                            │                                    │
│                                            ▼                                    │
│  3. EXPLOIT: Call admin_withdraw with UserVault instead of Pool                 │
│     ┌───────────────────────────────────────────────────────────────────┐       │
│     │  admin_withdraw(                                                  │       │
│     │      pool: USER_VAULT_PDA,  // <-- Not the real pool!            │       │
│     │      authority: ATTACKER,                                         │       │
│     │      amount: DRAIN_AMOUNT                                         │       │
│     │  )                                                                │       │
│     └───────────────────────────────────────────────────────────────────┘       │
│                                            │                                    │
│                                            ▼                                    │
│  4. VULNERABLE CODE: Skips discriminator, reads data as Pool                    │
│     ┌───────────────────────────────────────────────────────────────────┐       │
│     │  let data = pool_info.try_borrow_data()?;                         │       │
│     │  let authority = &data[8..40];  // Reads UserVault.owner!         │       │
│     │                                                                   │       │
│     │  if authority == signer.key() {  // TRUE! Attacker signed!        │       │
│     │      transfer_funds();            // EXPLOIT SUCCEEDS            │       │
│     │  }                                                                │       │
│     └───────────────────────────────────────────────────────────────────┘       │
│                                                                                 │
│  5. RESULT: Attacker drains funds by impersonating pool admin!                 │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## The Vulnerable Code

```rust
#[derive(Accounts)]
pub struct AdminWithdraw<'info> {
    /// CHECK: VULNERABILITY - Using UncheckedAccount allows ANY account!
    #[account(mut)]
    pub pool: UncheckedAccount<'info>,  // Should be Account<'info, Pool>
    
    pub authority: Signer<'info>,
    
    #[account(mut)]
    pub recipient: UncheckedAccount<'info>,
}

pub fn admin_withdraw(ctx: Context<AdminWithdraw>, amount: u64) -> Result<()> {
    let pool_info = &ctx.accounts.pool;
    let data = pool_info.try_borrow_data()?;
    
    // VULNERABILITY: Skip discriminator without validating it!
    let authority_bytes: [u8; 32] = data[8..40].try_into().unwrap();
    let pool_authority = Pubkey::from(authority_bytes);
    
    // This check passes when UserVault is passed instead of Pool!
    // Because UserVault.owner (attacker) is at the same offset as Pool.authority
    require!(pool_authority == ctx.accounts.authority.key(), PoolError::NotAuthority);
    
    // Attacker drains funds...
    Ok(())
}
```

---

## The Fix: Discriminator Validation

### Option 1: Use Anchor's `Account<'info, T>` (Recommended)

```rust
#[derive(Accounts)]
pub struct AdminWithdraw<'info> {
    /// SECURE: Account<'info, Pool> validates discriminator automatically
    #[account(
        mut,
        constraint = pool.authority == authority.key() @ PoolError::NotAuthority
    )]
    pub pool: Account<'info, Pool>,  // Anchor validates discriminator!
    
    pub authority: Signer<'info>,
    
    #[account(mut)]
    pub recipient: UncheckedAccount<'info>,
}
```

### Option 2: Manual Discriminator Validation

```rust
pub fn admin_withdraw_manual(ctx: Context<AdminWithdrawManual>, amount: u64) -> Result<()> {
    let pool_info = &ctx.accounts.pool;
    let data = pool_info.try_borrow_data()?;
    
    // SECURE: Validate discriminator FIRST!
    let discriminator = &data[0..8];
    let expected = Pool::discriminator();
    require!(discriminator == expected, PoolError::InvalidDiscriminator);
    
    // SECURE: Validate program ownership
    require!(pool_info.owner == &crate::ID, PoolError::WrongProgramOwner);
    
    // Now safe to deserialize and use
    let pool = Pool::try_deserialize_unchecked(&mut &data[8..])?;
    // ...
}
```

### Option 3: Defense in Depth - Explicit Type Markers

```rust
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq)]
pub enum AccountType {
    Pool,
    UserVault,
}

#[account]
pub struct Pool {
    pub account_type: AccountType,  // Explicit type marker
    pub authority: Pubkey,
    pub total_liquidity: u64,
    pub is_active: bool,
}

// In instruction:
require!(pool.account_type == AccountType::Pool, PoolError::WrongAccountType);
```

---

## Prevention Checklist

| Check | Implementation |
|-------|----------------|
| Use typed accounts | `Account<'info, T>` instead of `UncheckedAccount` |
| Validate discriminator | Check first 8 bytes match expected type |
| Validate program ownership | `account.owner == &crate::ID` |
| Add explicit type markers | `account_type: AccountType` field |
| PDA seeds validation | Ensure PDAs are derived with expected seeds |

---

## Real-World Impact

| Exploit | Loss | Cause |
|---------|------|-------|
| Cashio | $52M | Account confusion in stable coin protocol |
| Various DeFi | $10M+ | Type confusion in lending protocols |
| Multiple protocols | Ongoing | Variations of this bug class |

---

## Running Tests

```bash
cd anchor
yarn install
anchor build
anchor test
```

**Test Coverage:**
1. Creates legitimate pool with admin authority
2. User creates vault and deposits 5 SOL into pool
3. Attacker creates vault and deposits 3 SOL (sets up exploit by populating `deposited_amount`)
4. **EXPLOIT**: Attacker calls `admin_withdraw` passing their UserVault instead of Pool
   - Program reads `UserVault.owner` as `Pool.authority` (attacker's pubkey)
   - Authority check passes because attacker signed the transaction
   - Funds are drained from the vault account
5. **FIX**: Fixed program rejects the attack due to automatic discriminator validation
6. Admin can still perform legitimate withdrawals on the fixed program

---

## Key Takeaways

1. **Never use `UncheckedAccount` for typed data** - Always use `Account<'info, T>`
2. **Discriminators are critical** - The first 8 bytes identify the account type
3. **Memory layouts can overlap** - Different structs may have fields at same offsets
4. **Defense in depth** - Add explicit type markers, validate ownership, use PDA constraints
5. **Audit all manual deserialization** - Any skipping of discriminator is a red flag

---

## Related Vulnerabilities

- **Type Confusion (Module 05)**: Similar byte-level misinterpretation
- **Signature Bugs (Module 08)**: Authorization bypass through different means
- **Storage Collision (Module 06)**: Memory layout issues during upgrades
