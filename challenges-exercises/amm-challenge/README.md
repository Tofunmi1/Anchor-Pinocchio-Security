# AMM (Automated Market Maker) Security Challenge

## Overview

This challenge contains a vulnerable AMM implementation with **8 critical security bugs**. Your goal is to identify and exploit each vulnerability, then understand how the fixed version addresses them.

| # | Vulnerability | Severity | Impact |
|---|--------------|----------|--------|
| 01 | Missing Slippage Protection | Critical | Users drained via sandwich attacks |
| 02 | Integer Overflow in K Calculation | Critical | Pool invariant broken, funds stolen |
| 03 | Price Oracle Manipulation | Critical | Flash loan price manipulation |
| 04 | Missing Signer Check on Withdraw | Critical | Anyone can drain LP funds |
| 05 | Fee Calculation Rounding Error | High | Fee stealing via dust attacks |
| 06 | Reentrancy in Swap | High | Double-spend via callback |
| 07 | Missing Owner Check on Pool | High | Fake pool substitution |
| 08 | Unprotected Initialize | Medium | Pool hijacking |

---

## How AMMs Work

### Constant Product Formula

AMMs use the formula `x * y = k` where:
- `x` = reserve of token A
- `y` = reserve of token B  
- `k` = constant product (invariant)

```
Before swap: x * y = k
After swap:  (x + Δx) * (y - Δy) = k

Therefore:   Δy = y - k/(x + Δx)
```

### Price Impact

The price changes based on trade size relative to reserves:

```
Spot Price = y / x

Large trades → Large price impact
Small reserves → Higher slippage
```

---

## Directory Structure

```
amm-challenge/
├── README.md
└── anchor/
    ├── Anchor.toml
    ├── Cargo.toml
    ├── package.json
    ├── programs/
    │   ├── amm-vulnerable/       # Contains ALL 8 bugs
    │   │   ├── Cargo.toml
    │   │   └── src/lib.rs
    │   └── amm-fixed/            # All bugs patched
    │       ├── Cargo.toml
    │       └── src/lib.rs
    └── tests/
        ├── amm-exploit.ts        # Exploit demonstrations
        └── amm-fixed.ts          # Verify fixes work
```

---

## Vulnerability Deep Dive

### 01 - Missing Slippage Protection

**The Bug:**
```rust
// VULNERABLE - No minimum output check
pub fn swap(ctx: Context<Swap>, amount_in: u64) -> Result<()> {
    let amount_out = calculate_output(amount_in, reserve_a, reserve_b);
    // Missing: require!(amount_out >= min_amount_out)
    transfer_tokens(amount_out)?;
}
```

**The Exploit:**
An attacker can sandwich your transaction:
1. Front-run: Buy tokens, moving price up
2. Your swap executes at worse price
3. Back-run: Sell tokens, profiting from your loss

**The Fix:**
```rust
pub fn swap(ctx: Context<Swap>, amount_in: u64, min_amount_out: u64) -> Result<()> {
    let amount_out = calculate_output(...);
    require!(amount_out >= min_amount_out, AmmError::SlippageExceeded);
    // ...
}
```

---

### 02 - Integer Overflow in K Calculation

**The Bug:**
```rust
// VULNERABLE - u64 overflow possible
let k = reserve_a * reserve_b;  // Can overflow with large reserves!
```

With reserves > 2^32, the multiplication overflows:
- `4_294_967_296 * 4_294_967_296 = 0` (overflow!)

**The Exploit:**
1. Provide huge initial liquidity
2. Overflow makes k = 0 or small value
3. Drain pool with tiny swap

**The Fix:**
```rust
// Use u128 for intermediate calculations
let k: u128 = (reserve_a as u128) * (reserve_b as u128);
```

---

### 03 - Price Oracle Manipulation

**The Bug:**
```rust
// VULNERABLE - Uses spot price directly
pub fn get_price(ctx: Context<GetPrice>) -> Result<u64> {
    let pool = &ctx.accounts.pool;
    Ok(pool.reserve_b / pool.reserve_a)  // Manipulable!
}
```

**The Exploit:**
1. Flash loan massive amount of token A
2. Swap into pool → price crashes
3. Use manipulated price in external protocol
4. Profit, repay flash loan

**The Fix:**
```rust
// Use TWAP (Time-Weighted Average Price)
pub fn get_price(ctx: Context<GetPrice>) -> Result<u64> {
    let pool = &ctx.accounts.pool;
    let time_elapsed = Clock::get()?.unix_timestamp - pool.last_update;
    
    // Use cumulative price for TWAP
    let twap = pool.price_cumulative / time_elapsed;
    Ok(twap)
}
```

---

### 04 - Missing Signer Check on Withdraw

**The Bug:**
```rust
#[derive(Accounts)]
pub struct RemoveLiquidity<'info> {
    #[account(mut)]
    pub pool: Account<'info, Pool>,
    /// CHECK: VULNERABLE - Not a Signer!
    pub lp_owner: AccountInfo<'info>,  // Should be Signer<'info>
}
```

**The Exploit:**
Anyone can call withdraw with victim's pubkey as `lp_owner`.

**The Fix:**
```rust
pub lp_owner: Signer<'info>,
```

---

### 05 - Fee Calculation Rounding Error

**The Bug:**
```rust
// VULNERABLE - Rounds down, loses precision
let fee = amount_in * FEE_BPS / 10000;  // 0.3% fee
let amount_after_fee = amount_in - fee;
```

For small amounts: `99 * 30 / 10000 = 0` (no fee!)

**The Exploit:**
Make many tiny swaps → pay zero fees → drain fee revenue

**The Fix:**
```rust
// Round up to ensure fee is always collected
let fee = (amount_in * FEE_BPS + 9999) / 10000;
// Or use checked math with proper precision
let fee = amount_in.checked_mul(FEE_BPS)
    .ok_or(AmmError::Overflow)?
    .checked_add(9999)
    .ok_or(AmmError::Overflow)?
    .checked_div(10000)
    .ok_or(AmmError::Overflow)?;
```

---

### 06 - Reentrancy in Swap

**The Bug:**
```rust
// VULNERABLE - State updated AFTER external call
pub fn swap(ctx: Context<Swap>, amount_in: u64) -> Result<()> {
    let amount_out = calculate_output(...);
    
    // External call first (vulnerable!)
    transfer_tokens_out(amount_out)?;
    
    // State update after (too late!)
    pool.reserve_a += amount_in;
    pool.reserve_b -= amount_out;
}
```

**The Exploit:**
If transfer calls back into swap, old reserves are used again.

**The Fix:**
```rust
// Checks-Effects-Interactions pattern
pub fn swap(ctx: Context<Swap>, amount_in: u64) -> Result<()> {
    let amount_out = calculate_output(...);
    
    // 1. Checks (already done)
    // 2. Effects (update state FIRST)
    pool.reserve_a += amount_in;
    pool.reserve_b -= amount_out;
    
    // 3. Interactions (external calls LAST)
    transfer_tokens_out(amount_out)?;
}
```

---

### 07 - Missing Owner Check on Pool

**The Bug:**
```rust
#[derive(Accounts)]
pub struct Swap<'info> {
    /// CHECK: VULNERABLE - No owner verification
    #[account(mut)]
    pub pool: UncheckedAccount<'info>,
}
```

**The Exploit:**
1. Create fake pool account (owned by System Program)
2. Write crafted data with favorable reserves
3. Get cheap tokens from "swap"

**The Fix:**
```rust
#[account(mut)]
pub pool: Account<'info, Pool>,  // Verifies owner + discriminator
```

---

### 08 - Unprotected Initialize

**The Bug:**
```rust
// VULNERABLE - No authority check
pub fn initialize(ctx: Context<Initialize>, fee: u64) -> Result<()> {
    let pool = &mut ctx.accounts.pool;
    pool.authority = ctx.accounts.payer.key();  // First caller becomes authority!
    pool.fee = fee;
}
```

**The Exploit:**
Front-run legitimate initialization → become pool authority → set malicious fee

**The Fix:**
```rust
#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + Pool::INIT_SPACE,
        seeds = [b"pool", token_a.key().as_ref(), token_b.key().as_ref()],
        bump
    )]
    pub pool: Account<'info, Pool>,
    // PDA seeds ensure deterministic, unique pool per token pair
}
```

---

## Your Challenge

### Part 1: Exploit the Vulnerable Contract

Write tests that demonstrate each vulnerability:

1. **Sandwich Attack** - Front-run a swap, extract value
2. **Overflow Attack** - Break the k invariant
3. **Oracle Manipulation** - Flash loan price attack
4. **Unauthorized Withdraw** - Drain LP without signing
5. **Fee Bypass** - Swap without paying fees
6. **Reentrancy** - Double-spend via callback
7. **Fake Pool** - Substitute crafted pool data
8. **Hijack Init** - Front-run initialization

### Part 2: Verify the Fixes

Run the fixed version and confirm:
- All exploits fail with appropriate errors
- Legitimate operations still work
- Edge cases are handled properly

---

## Running the Challenge

```bash
cd anchor
yarn install
anchor build
anchor test
```

---

## Hints

<details>
<summary>Hint 1: Sandwich Attack</summary>

The mempool is public. An attacker can see your pending swap and:
- Submit a buy order with higher gas (front-run)
- Let your swap execute
- Submit a sell order (back-run)

Key insight: Without slippage protection, you accept ANY output.
</details>

<details>
<summary>Hint 2: Overflow</summary>

`u64::MAX = 18,446,744,073,709,551,615`

When you multiply two u64 values, the result can exceed u64::MAX.
In Rust (release mode), this wraps around to a small number.

What happens if k becomes 0 or very small?
</details>

<details>
<summary>Hint 3: Reentrancy</summary>

Solana's runtime prevents most reentrancy, but CPI can create similar issues.
The key is: what state is the program in when an external call happens?

If reserves haven't been updated yet, a callback sees stale values.
</details>

---

## References

- [Uniswap V2 Whitepaper](https://uniswap.org/whitepaper.pdf)
- [Constant Product AMM Math](https://github.com/runtimeverification/verified-smart-contracts/blob/uniswap/uniswap/x-y-k.pdf)
- [Sealevel Attacks](https://github.com/coral-xyz/sealevel-attacks)
- [Solana Security Best Practices](https://docs.solana.com/developing/programming-model/security)
