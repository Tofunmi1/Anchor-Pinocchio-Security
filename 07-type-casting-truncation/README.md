# 07 - Type Casting & Truncation Vulnerabilities

## Overview

This module demonstrates **type casting vulnerabilities** in Solana programs, specifically when using the `as` keyword to cast between integer types.

## The Vulnerability

Using `as` for type casting in Rust can **silently truncate values**:

```rust
// ❌ VULNERABLE: Silent truncation
let result_u128: u128 = large_calculation();
let result: u64 = result_u128 as u64;  // High bits silently discarded!
```

### What Happens

When a `u128` value exceeds `u64::MAX` (18,446,744,073,709,551,615):

```
Value:    0x0000_0001_5833_1A55_B2AA_0000
              ^^^^^^^^ ^^^^^^^^^^^^^^^^
              Discarded   Kept as u64
```

**Result**: `2 × 10^19` becomes `1,553,255,926,290,448,384` (83% loss!)

## The Fix

Use `try_from` to detect overflow and return an error:

```rust
//  SAFE: Error on overflow
let result: u64 = u64::try_from(result_u128)
    .map_err(|_| error!(ErrorCode::Overflow))?;
```

## Programs

| Program | Description |
|---------|-------------|
| `truncation-vulnerable` | Uses `as u64` - silent truncation |
| `truncation-fixed` | Uses `try_from` - rejects overflow |

## Running Tests

```bash
cd anchor
anchor test
```

## Test Output

```
07 - Type Casting Truncation
  Vulnerable: Silent Truncation
    ✔ VULNERABILITY: Result truncated silently
  Fixed: try_from prevents truncation
    ✔ FIX: Calculation rejected when overflow would occur
    ✔ FIX: Small calculation succeeds
```

## Key Takeaways

1. **Never use `as` for downcasting** (u128→u64, u64→u32, etc.)
2. **Use `try_from`** to detect and handle overflow
3. **Use `checked_*` methods** for arithmetic operations

---

## Anchor vs Pinocchio Comparison

### Anchor Implementation

```rust
// Vulnerable - uses `as` which truncates
pub fn calculate(ctx: Context<Calculate>, a: u64, b: u64) -> Result<()> {
    let result_u128 = (a as u128) * (b as u128);
    
    // BUG: Silent truncation!
    let result = result_u128 as u64;
    
    ctx.accounts.result.value = result;
    Ok(())
}

// Fixed - uses try_from
pub fn calculate(ctx: Context<Calculate>, a: u64, b: u64) -> Result<()> {
    let result_u128 = (a as u128) * (b as u128);
    
    // Returns error if result doesn't fit in u64
    let result = u64::try_from(result_u128)
        .map_err(|_| error!(ErrorCode::Overflow))?;
    
    ctx.accounts.result.value = result;
    Ok(())
}
```

### Pinocchio Implementation

```rust
// Vulnerable - uses `as` which truncates
fn process_calculate(accounts: &[AccountInfo], a: u64, b: u64) -> ProgramResult {
    let result_u128 = (a as u128) * (b as u128);
    
    // BUG: `as u64` silently truncates!
    let result = result_u128 as u64;
    
    let data = unsafe { result_account.borrow_mut_data_unchecked() };
    data[0..8].copy_from_slice(&result.to_le_bytes());
    Ok(())
}

// Fixed - uses try_from
fn process_calculate(accounts: &[AccountInfo], a: u64, b: u64) -> ProgramResult {
    let result_u128 = (a as u128) * (b as u128);
    
    // try_from returns Err if value doesn't fit
    let result = u64::try_from(result_u128).map_err(|_| {
        msg!("Result {} exceeds u64::MAX", result_u128);
        ProgramError::ArithmeticOverflow
    })?;
    
    let data = unsafe { result_account.borrow_mut_data_unchecked() };
    data[0..8].copy_from_slice(&result.to_le_bytes());
    Ok(())
}
```

### Framework Comparison

| Aspect | Anchor | Pinocchio |
|--------|--------|-----------|
| Casting method | Same Rust methods | Same Rust methods |
| Error handling | `error!(ErrorCode::Overflow)` | `ProgramError::ArithmeticOverflow` |
| The vulnerability | Identical - `as` truncates silently | Identical - `as` truncates silently |
| The fix | Use `try_from` | Use `try_from` |

**Key insight**: This vulnerability is a Rust language issue, not framework-specific. Both Anchor and Pinocchio programs must avoid `as` downcasting.

---

## File Structure

```
07-type-casting-truncation/
├── README.md
├── anchor/
│   └── programs/
│       ├── truncation-vulnerable/
│       └── truncation-fixed/
└── pinocchio/
    └── programs/
        ├── truncation-vulnerable/
        └── truncation-fixed/
```

---

## References

- [Rust Type Casting](https://doc.rust-lang.org/std/convert/trait.TryFrom.html)
- [Numeric Casts](https://doc.rust-lang.org/reference/expressions/operator-expr.html#type-cast-expressions)
