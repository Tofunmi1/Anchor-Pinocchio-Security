# 03 - Logic & Arithmetic Vulnerabilities

This category covers critical vulnerabilities related to mathematical operations and program logic errors. These bugs are extremely common in DeFi protocols and early Solana programs, often leading to complete protocol drainage.

## Challenges

### 1. Integer Overflow/Underflow

**The Mechanics:**
Rust's `u64` type stores numbers from `0` to `18,446,744,073,709,551,615`. It has no concept of negative numbers.
- **Overflow**: When a number exceeds the maximum, it "wraps around" to the beginning.
  - `MAX + 1` → `0`
- **Underflow**: When a number goes below zero, it "wraps around" to the maximum.
  - `0 - 1` → `MAX`

**What happens at the bit level?**
Imagine `u8` (0-255) for simplicity:
- `0` in binary is `0000 0000`
- Subtracting `1` triggers a borrow that cascades through all bits:
- Result is `1111 1111` (which is 255 in decimal)

**Real-World Example:**
Imagine a Staking Contract.
- **State**: User has staked **100 tokens**.
- **Action**: User tries to withdraw **200 tokens**.
- **Vulnerable Code**:
  ```rust
  // Unsafe "wrapping" subtraction
  user.staked_balance = user.staked_balance.wrapping_sub(amount);
  // Calculation: 100 - 200
  // Result in u64: 18,446,744,073,709,551,516
  ```
- **Consequence**: The user's balance is updated to a massive number. They can now withdraw the entire pool.

**The Fix:**
Use checked arithmetic. It returns an `Option` (`Some(result)` or `None`).
```rust
// Returns Error if underflow occurs
user.staked_balance = user.staked_balance
    .checked_sub(amount)
    .ok_or(ErrorCode::InsufficientFunds)?;
```

---

### 2. Precision Loss (Rounding Errors)

**The Mechanics:**
Solana programs generally don't use floating point numbers (`f64`) because they are non-deterministic across different hardware, which breaks consensus. We use Integers (`u64`, `u128`).
- **Integer Division**: Discards the remainder.
- `10 / 100 = 0` (Not 0.1)
- `99 / 100 = 0` (Not 0.99)

**The "Cliff" Problem:**
Any time you divide a smaller number by a larger number, the result "falls off the cliff" to zero. This destroys value instantly.

**Vulnerable Scenario: The Pro-Rata Share**
A vault calculates how many tokens to give a user based on their % ownership of the pool.
- Users withdraws: **10 shares**
- Total shares: **1,000**
- Total Vault Assets: **10,000,000 USDC**

**Bad Logic (Divide First):**
```rust
// 1. Calculate percentage ownership
// 10 / 1,000 = 0 (Data loss here!)
let ownership_pct = shares / total_shares; 

// 2. Calculate asset amount
// 0 * 10,000,000 = 0
let amount_out = ownership_pct * total_assets;
```
**Result**: User gets **0 USDC**.

**Fixed Logic (Multiply First):**
By multiplying first, we make the number massive *before* we divide it. This preserves the "fractional" information inside the upper digits of the large integer.

```rust
// 1. Cast to u128 to prevent overflow
// We use u128 because (u64::MAX * u64::MAX) would overflow a u64
let numerator = (shares as u128) * (total_assets as u128);
// Result: 100,000,000

// 2. Divide by total shares
let amount_out = numerator / (total_shares as u128);
// Result: 100,000
```
**Result**: User gets exactly **100,000 USDC**.

**Key Takeaway**: 
In integer math, `(a / b) * c` is **NOT** equal to `(a * c) / b`. 
Always use the latter form.

---

## Anchor vs Pinocchio Comparison

### Anchor Implementation

```rust
// Vulnerable - wrapping arithmetic
pool.total_staked = pool.total_staked.wrapping_add(amount);
user.staked_amount = user.staked_amount.wrapping_sub(amount);

// Fixed - checked arithmetic with Anchor error
pool.total_staked = pool.total_staked
    .checked_add(amount)
    .ok_or(ArithmeticError::Overflow)?;

user.staked_amount = user.staked_amount
    .checked_sub(amount)
    .ok_or(ArithmeticError::Underflow)?;
```

### Pinocchio Implementation

```rust
// Vulnerable - wrapping arithmetic
let total_staked = u64::from_le_bytes(pool_data[32..40].try_into().unwrap());
let new_total = total_staked.wrapping_add(amount);  // BUG!
pool_data[32..40].copy_from_slice(&new_total.to_le_bytes());

// Fixed - checked arithmetic with ProgramError
let new_total = total_staked
    .checked_add(amount)
    .ok_or(ProgramError::ArithmeticOverflow)?;

let new_staked = staked_amount
    .checked_sub(amount)
    .ok_or(ProgramError::ArithmeticOverflow)?;
```

### Framework Comparison

| Aspect | Anchor | Pinocchio |
|--------|--------|-----------|
| Arithmetic methods | Same Rust std methods | Same Rust std methods |
| Error types | Custom `#[error_code]` | `ProgramError` variants |
| Data access | Type-safe struct fields | Raw byte offsets |
| Compile-time safety | Same | Same |

Both frameworks use the same Rust arithmetic methods. The key is to use:
- `checked_add()` instead of `+` or `wrapping_add()`
- `checked_sub()` instead of `-` or `wrapping_sub()`
- `checked_mul()` instead of `*` or `wrapping_mul()`

---

## File Structure

```
03-logic-and-arithmetic-bugs/
├── README.md
├── anchor/
│   └── programs/
│       ├── 01-integer-overflow-vulnerable/
│       ├── 01-integer-overflow-fixed/
│       ├── 02-precision-loss-vulnerable/
│       └── 02-precision-loss-fixed/
└── pinocchio/
    └── programs/
        ├── integer-overflow-vulnerable/
        └── integer-overflow-fixed/
```

## Running Tests

```bash
cd anchor
anchor test
```

## Resources

- [Rust Integer Overflow](https://doc.rust-lang.org/book/ch03-02-data-types.html#integer-overflow)
- [Solana Security Workshop - Math](https://github.com/coral-xyz/sealevel-attacks/tree/master/programs/4-integer-overflow)
- [How to Avoid Precision Loss](https://medium.com/coinmonks/math-in-solidity-part-3-percents-and-proportions-4db014e080b1)

