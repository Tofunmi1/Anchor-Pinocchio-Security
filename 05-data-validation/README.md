# Data Validation Vulnerabilities

## Overview

Data validation bugs occur when programs accept user input without proper bounds checking or format validation, leading to unexpected behavior or exploitable states.

| # | Vulnerability | Severity | Description |
|---|--------------|----------|-------------|
| 01 | Missing Range Check | High | Accepting values outside expected bounds |
| 02 | Type Confusion | High | Accepting wrong account types |
| 03 | Duplicate Accounts | Medium | Same account passed for multiple parameters |

---

## Implementations

```
05-data-validation/
├── README.md
├── anchor/
│   └── programs/
│       ├── 01-type-confusion-vulnerable/
│       ├── 01-type-confusion-fixed/
│       ├── 02-range-check-vulnerable/
│       ├── 02-range-check-fixed/
│       ├── 03-duplicate-account-vulnerable/
│       └── 03-duplicate-account-fixed/
└── pinocchio/
    └── programs/
        ├── range-check-vulnerable/
        └── range-check-fixed/
```

---

## The Vulnerability: Missing Range Checks

### Attack Scenario

1. Admin function accepts a `fee_bps` parameter (basis points)
2. No validation that fee is within reasonable bounds
3. Attacker (or malicious admin) sets fee to 10000 (100%)
4. All user funds are drained as "fees"

---

## Anchor vs Pinocchio Comparison

### Anchor Implementation

```rust
// Vulnerable - no validation
pub fn set_fee(ctx: Context<SetFee>, fee_bps: u16) -> Result<()> {
    ctx.accounts.config.fee_bps = fee_bps;  // Could be 10000 (100%)!
    Ok(())
}

// Fixed - explicit validation
pub fn set_fee(ctx: Context<SetFee>, fee_bps: u16) -> Result<()> {
    require!(fee_bps <= 1000, ConfigError::FeeTooHigh);  // Max 10%
    ctx.accounts.config.fee_bps = fee_bps;
    Ok(())
}
```

### Pinocchio Implementation

```rust
const MAX_FEE_BPS: u16 = 1000;  // Max 10%

// Vulnerable - no validation
fn process_set_fee(accounts: &[AccountInfo], fee_bps: u16) -> ProgramResult {
    let config_data = unsafe { config.borrow_mut_data_unchecked() };
    
    // BUG: No validation on fee_bps!
    config_data[0..2].copy_from_slice(&fee_bps.to_le_bytes());
    Ok(())
}

// Fixed - explicit validation
fn process_set_fee(accounts: &[AccountInfo], fee_bps: u16) -> ProgramResult {
    // Validate input range
    if fee_bps > MAX_FEE_BPS {
        msg!("Fee {} exceeds maximum {}", fee_bps, MAX_FEE_BPS);
        return Err(ProgramError::InvalidArgument);
    }
    
    let config_data = unsafe { config.borrow_mut_data_unchecked() };
    config_data[0..2].copy_from_slice(&fee_bps.to_le_bytes());
    Ok(())
}
```

### Framework Comparison

| Aspect | Anchor | Pinocchio |
|--------|--------|-----------|
| Validation method | `require!` macro | Manual `if` checks |
| Error handling | Custom `#[error_code]` | `ProgramError::InvalidArgument` |
| Constraint syntax | `constraint = expr @ Error` | Explicit conditionals |
| Type coercion | Automatic via Borsh | Manual byte parsing |

---

## Common Validation Patterns

### Range Checks

```rust
// Anchor
require!(amount > 0, Error::ZeroAmount);
require!(amount <= MAX_AMOUNT, Error::AmountTooLarge);

// Pinocchio
if amount == 0 { return Err(ProgramError::InvalidArgument); }
if amount > MAX_AMOUNT { return Err(ProgramError::InvalidArgument); }
```

### Relationship Checks

```rust
// Anchor
#[account(constraint = vault.authority == authority.key() @ Error::Unauthorized)]
pub vault: Account<'info, Vault>,

// Pinocchio
let stored_authority = &vault_data[0..32];
if stored_authority != authority.key().as_ref() {
    return Err(ProgramError::InvalidAccountData);
}
```

---

## Running Tests

```bash
cd anchor
anchor test
```

---

## References

- [Anchor Constraints](https://www.anchor-lang.com/docs/account-constraints)
- [Solana Input Validation](https://docs.solana.com/developing/programming-model/input-validation)
