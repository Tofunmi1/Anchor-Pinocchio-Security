# 05 - Data Validation Vulnerabilities

This category covers vulnerabilities where programs fail to properly validate the **format**, **type**, or **bounds** of input data. These bugs often arise from trusting user input without verification.

---

## Overview

| Vulnerability | Risk Level | Impact |
|---------------|------------|--------|
| Type Confusion | Critical | Privilege escalation by substituting account types |
| Missing Range Check | High | Invalid state, game exploits, potential overflows |
| Duplicate Account | Critical | Infinite money glitch via self-transfer aliasing |

---

## Challenges

### 1. Type Confusion (Account Discriminator)

In Anchor, each account type has an 8-byte discriminator prefix that identifies its type. If a program manually deserializes account data without checking this discriminator, attackers can substitute different account types with matching field layouts.

**Memory Layout:**
```
┌─────────────────────────────────────────────────────────────────┐
│                      TYPE CONFUSION                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Account Memory Layout Comparison:                              │
│                                                                 │
│  User Account:                                                  │
│  ┌──────────────────────────┬─────────────────────────┐         │
│  │ User Discriminator (8B)  │ id: u64 (8B)            │         │
│  └──────────────────────────┴─────────────────────────┘         │
│                              ↑                                  │
│  AdminConfig Account:        │ (Same offset = 8)                │
│  ┌──────────────────────────┼─────────────────────────┐         │
│  │ Admin Discriminator (8B) │ admin_id: u64 (8B)      │         │
│  └──────────────────────────┴─────────────────────────┘         │
│                                                                 │
│  Attack Steps:                                                  │
│  1. Attacker creates User account with id = target_admin_id     │
│  2. Attacker passes User account to admin_withdraw instruction  │
│  3. Program skips 8-byte discriminator, reads id as admin_id    │
│  4. Admin authorization check passes                            │
│  5. Attacker gains unauthorized admin privileges                │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Vulnerable Pattern:**
```rust
// VULNERABLE: Manual deserialization without discriminator check
#[derive(Accounts)]
pub struct AdminWithdraw<'info> {
    /// CHECK: Accepts any account - discriminator not verified
    pub admin_config: UncheckedAccount<'info>,
    pub authority: Signer<'info>,
}

// In instruction logic:
let account_data = ctx.accounts.admin_config.try_borrow_data()?;
let mut data_slice = &account_data[8..]; // Skips discriminator!
let config = AdminConfig::deserialize(&mut data_slice)?;
```

**Secure Pattern:**
```rust
// SECURE: Anchor validates discriminator automatically
#[derive(Accounts)]
pub struct AdminWithdraw<'info> {
    pub admin_config: Account<'info, AdminConfig>, // Type-safe
    pub authority: Signer<'info>,
}
```

---

### 2. Range Check (Invalid Inputs)

Programs often assume inputs will fall within logical bounds but fail to enforce these constraints. Attackers can pass extreme values to break game balance, cause arithmetic overflow, or create invalid state.

**Attack Scenario:**
```
┌─────────────────────────────────────────────────────────────────┐
│                     MISSING RANGE CHECK                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Game Design:                                                   │
│    - Valid levels: 1 to 100                                     │
│    - Health formula: health = level * 100                       │
│    - Expected max health: 10,000                                │
│                                                                 │
│  Normal Usage:                                                  │
│    set_level(50)  --> health = 5,000   [OK]                     │
│    set_level(100) --> health = 10,000  [OK, max]                │
│                                                                 │
│  Exploit:                                                       │
│    set_level(255) --> health = 25,500  [2.5x intended max!]     │
│                                                                 │
│  Impact:                                                        │
│    - Player has 2.5x more health than any legitimate player     │
│    - Complete game balance destruction                          │
│    - "God mode" character with impossible stats                 │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Vulnerable Pattern:**
```rust
// VULNERABLE: Accepts any u8 value (0-255)
pub fn set_level(ctx: Context<SetLevel>, level: u8) -> Result<()> {
    let character = &mut ctx.accounts.character;
    character.level = level;                    // No validation!
    character.health = (level as u64) * 100;    // Can produce 25,500
    Ok(())
}
```

**Secure Pattern:**
```rust
// SECURE: Validates input bounds before processing
const MAX_LEVEL: u8 = 100;

pub fn set_level(ctx: Context<SetLevel>, level: u8) -> Result<()> {
    require!(level >= 1 && level <= MAX_LEVEL, GameError::InvalidLevel);
    
    let character = &mut ctx.accounts.character;
    character.level = level;
    character.health = (level as u64) * 100;    // Max is now 10,000
    Ok(())
}
```

---

### 3. Duplicate Account (Aliasing)

When the same mutable account is passed multiple times to an instruction, Anchor deserializes each reference into a separate in-memory struct. After instruction execution, both structs are serialized back to the same account, with the last write winning.

**Attack Mechanism:**
```
┌─────────────────────────────────────────────────────────────────┐
│                   DUPLICATE ACCOUNT (ALIASING)                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Initial State: Wallet A has balance = 1000                     │
│                                                                 │
│  Attack: transfer(from = A, to = A, amount = 100)               │
│                                                                 │
│  Step-by-Step Execution:                                        │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │                                                            │ │
│  │  1. DESERIALIZE (Anchor reads account twice):              │ │
│  │     from = { balance: 1000 }  <-- Read from Wallet A       │ │
│  │     to   = { balance: 1000 }  <-- Read from Wallet A again │ │
│  │                                                            │ │
│  │  2. EXECUTE (Instructions modify separate structs):        │ │
│  │     from.balance -= 100  -->  from = { balance: 900 }      │ │
│  │     to.balance += 100    -->  to   = { balance: 1100 }     │ │
│  │                                                            │ │
│  │  3. SERIALIZE (Anchor writes both back):                   │ │
│  │     Write from (900) to Wallet A                           │ │
│  │     Write to (1100) to Wallet A  <-- OVERWRITES!           │ │
│  │                                                            │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                 │
│  Final State: Wallet A has balance = 1100                       │
│               (Created 100 tokens from nothing!)                │
│                                                                 │
│  Repeat Attack: Each call creates 100 more tokens               │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Vulnerable Pattern:**
```rust
// VULNERABLE: No check for duplicate accounts
#[derive(Accounts)]
pub struct Transfer<'info> {
    #[account(mut)]
    pub from: Account<'info, Wallet>,
    #[account(mut)]
    pub to: Account<'info, Wallet>,  // Can be same as 'from'
}

pub fn transfer(ctx: Context<Transfer>, amount: u64) -> Result<()> {
    ctx.accounts.from.balance -= amount;
    ctx.accounts.to.balance += amount;  // Last write wins!
    Ok(())
}
```

**Secure Pattern:**
```rust
// SECURE: Enforce distinct accounts
pub fn transfer(ctx: Context<Transfer>, amount: u64) -> Result<()> {
    // Check accounts are different BEFORE any mutations
    require_keys_neq!(
        ctx.accounts.from.key(), 
        ctx.accounts.to.key(), 
        WalletError::DuplicateAccount
    );
    
    ctx.accounts.from.balance -= amount;
    ctx.accounts.to.balance += amount;
    Ok(())
}
```

---

## Running Tests

```bash
cd anchor
anchor test
```

**Test Coverage:**
- Vulnerable programs: Demonstrate successful exploits
- Fixed programs: Verify exploits are properly rejected

---

## Key Takeaways

| Principle | Implementation |
|-----------|----------------|
| Use typed accounts | `Account<'info, T>` validates discriminators automatically |
| Validate all inputs | Always check bounds before processing user data |
| Check for duplicates | Use `require_keys_neq!` when accounts must be distinct |
| Defensive programming | Assume all inputs are malicious until validated |

---

## Quick Reference

**Type Confusion Prevention:**
```rust
// Replace UncheckedAccount with typed Account
pub config: Account<'info, AdminConfig>,
```

**Range Validation:**
```rust
require!(value >= MIN && value <= MAX, Error::OutOfBounds);
```

**Duplicate Detection:**
```rust
require_keys_neq!(account_a.key(), account_b.key(), Error::Duplicate);
```
