# 04 - CPI & PDA Vulnerabilities

Cross-Program Invocations (CPI) and Program Derived Addresses (PDA) are fundamental Solana primitives that enable composability. However, improper use leads to some of the most critical vulnerabilities.

---

## Table of Contents

1. [Unchecked Program ID](#1-unchecked-program-id)
2. [Unchecked PDA Derivation](#2-unchecked-pda-derivation)
3. [Arbitrary CPI Signer](#3-arbitrary-cpi-signer)
4. [Running Tests](#running-tests)
5. [Key Takeaways](#key-takeaways)

---

## Overview

| Vulnerability | Risk | Impact |
|---------------|------|--------|
| Unchecked Program ID | 🔴 Critical | Execute arbitrary programs, fake token transfers |
| Unchecked PDA | 🔴 Critical | Substitute fake accounts, bypass access control |
| Arbitrary CPI Signer | 🔴 Critical | Drain program-owned funds via PDA signing |

---

## 1. Unchecked Program ID

### The Vulnerability

When your program calls another program via CPI, you must verify the target's Program ID. If you accept an `UncheckedAccount`, an attacker can substitute a malicious program.

### Attack Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                     UNCHECKED PROGRAM ID                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. Your Program expects to call Token Program:                 │
│                                                                 │
│     Your Program ──CPI──> [???] Token Program                   │
│                                │                                │
│  2. Attacker passes a FAKE program that always returns Ok:      │
│                                                                 │
│     Your Program ──CPI──> [FAKE] Returns "Success"              │
│                                                                 │
│  3. Your program updates state: "User deposited 1M USDC"        │
│     (No actual transfer occurred!)                              │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Memory Layout

```
┌─────────────────────────────────────────────────────────────────┐
│                    ACCOUNT INFO STRUCTURE                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  AccountInfo {                                                  │
│      key: Pubkey,           // Account's public key             │
│      owner: Pubkey,         // ← CRITICAL: Who owns this acct   │
│      data: &[u8],           // Account data                     │
│      ...                                                        │
│  }                                                              │
│                                                                 │
│  For programs, `executable = true` and `owner = BPF Loader`     │
│                                                                 │
│  Token Program ID: TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA  │
│  Fake Program ID:  Attacker1111111111111111111111111111111111   │
│                                                                 │
│  If you don't check, both are valid "executable" accounts!      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Vulnerable Code

```rust
// ❌ VULNERABLE: Accepts any program
#[derive(Accounts)]
pub struct CpiLog<'info> {
    /// CHECK: No validation!
    pub target_program: UncheckedAccount<'info>,
}

pub fn cpi_log(ctx: Context<CpiLog>) -> Result<()> {
    let ix = Instruction {
        program_id: *ctx.accounts.target_program.key, // Attacker-controlled!
        accounts: vec![],
        data: b"Hello".to_vec(),
    };
    invoke(&ix, &[ctx.accounts.target_program.to_account_info()])?;
    Ok(())
}
```

### Fixed Code

```rust
//  SECURE: Anchor validates Program ID automatically
#[derive(Accounts)]
pub struct CpiLog<'info> {
    pub target_program: Program<'info, Token>,  // Must be Token Program
}
```

---

## 2. Unchecked PDA Derivation

### The Vulnerability

PDAs are derived from deterministic seeds like `[b"vault", authority.key()]`. If you only check account data (like `owner` field) without verifying the address derivation, attackers can pass fake accounts.

### Attack Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                       UNCHECKED PDA                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  EXPECTED: Vault PDA at seeds [b"vault", authority]             │
│            Address: 7x8y9z...                                   │
│                                                                 │
│  ATTACK:                                                        │
│  1. Attacker creates a fake Vault at random keypair:            │
│     - Address: RANDOM123...  (NOT a PDA!)                       │
│     - owner: victim.publicKey                                   │
│     - amount: 100                                               │
│                                                                 │
│  2. Attacker calls: withdraw(fake_vault, victim_sig)            │
│                                                                 │
│  3. Program checks: vault.owner == authority ✓                  │
│     (Passes! But vault address is not canonical PDA)            │
│                                                                 │
│  4. Attacker's fake vault is modified instead of real one       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Why This Matters

```
                    ┌─────────────────────────────────────┐
REAL PDA DERIVATION │ seeds = [b"vault", authority]       │
                    │ bump = find_program_address(seeds)  │
                    │ address = hash(seeds || bump)       │
                    └─────────────────────────────────────┘
                                    │
                                    ▼
                    ┌─────────────────────────────────────┐
                    │ CANONICAL ADDRESS: 7x8y9z...        │
                    │ This is the ONLY valid vault        │
                    └─────────────────────────────────────┘

                    ┌─────────────────────────────────────┐
FAKE ACCOUNT        │ Normal keypair: RANDOM123...        │
                    │ Attacker can set any data inside    │
                    └─────────────────────────────────────┘
                                    │
                                    ▼
                    ┌─────────────────────────────────────┐
                    │ ATTACKER-CONTROLLED ACCOUNT         │
                    │ Can fake owner, amount, etc.        │
                    └─────────────────────────────────────┘
```

### Vulnerable Code

```rust
// ❌ VULNERABLE: No PDA seed verification
#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]  // Only checks discriminator (account type)
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}

pub fn withdraw(ctx: Context<Withdraw>) -> Result<()> {
    // This check is INSUFFICIENT!
    require!(ctx.accounts.vault.owner == ctx.accounts.authority.key(), NotOwner);
    // Attacker passed a fake vault where owner = victim
    // The check passes, but we're operating on wrong vault!
}
```

### Fixed Code

```rust
//  SECURE: PDA derivation enforced
#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(
        mut,
        seeds = [b"vault", authority.key().as_ref()],  // Enforces canonical PDA
        bump,
        constraint = vault.owner == authority.key() @ NotOwner
    )]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}
```

---

## 3. Arbitrary CPI Signer

### The Vulnerability

PDAs can "sign" for CPIs using `invoke_signed`. If your program accepts user-supplied instruction data and signs it, attackers can craft any instruction to drain your PDA's assets.

### Attack Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                    ARBITRARY CPI SIGNER                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Program's PDA Treasury holds 10 SOL:                           │
│     PDA [b"treasury"] ─── Balance: 10 SOL                       │
│                                                                 │
│  ATTACK:                                                        │
│  1. Attacker crafts System::Transfer instruction data:          │
│     - from: PDA (treasury)                                      │
│     - to: Attacker wallet                                       │
│     - amount: 10 SOL                                            │
│                                                                 │
│  2. Attacker calls: proxied_cpi(transfer_instruction_data)      │
│                                                                 │
│  3. Program blindly signs the instruction with PDA seeds        │
│                                                                 │
│  4. RESULT: PDA: 0 SOL, Attacker: +10 SOL                       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Instruction Data Layout

```
┌─────────────────────────────────────────────────────────────────┐
│              SYSTEM PROGRAM TRANSFER INSTRUCTION                │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Byte Layout:                                                   │
│  ┌────────────┬────────────────────────────────────────────┐   │
│  │ Index [4]  │ Lamports [8 bytes, little-endian]          │   │
│  │ 0x02000000 │ 0x00ca9a3b00000000  (10 SOL = 10^10)       │   │
│  └────────────┴────────────────────────────────────────────┘   │
│                                                                 │
│  Attacker Message:                                              │
│  data = [2, 0, 0, 0] ++ amount.to_le_bytes()                   │
│                                                                 │
│  If your program lets users pass this `data`, they drain you!   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Vulnerable Code

```rust
// ❌ VULNERABLE: User controls instruction data
pub fn proxied_cpi(ctx: Context<ProxiedCpi>, data: Vec<u8>) -> Result<()> {
    let ix = Instruction {
        program_id: *ctx.accounts.target_program.key,
        accounts: vec![
            AccountMeta::new(*ctx.accounts.pda_signer.key, true),
            AccountMeta::new(*ctx.accounts.destination.key, false),
        ],
        data,  // USER-CONTROLLED! Can be System::Transfer
    };

    invoke_signed(&ix, ..., &[&[b"signer", &[bump]]])?;  // Signed blindly!
    Ok(())
}
```

### Fixed Code

```rust
//  SECURE: Program controls instruction construction
pub fn claim_reward(ctx: Context<ClaimReward>) -> Result<()> {
    const REWARD_AMOUNT: u64 = 10_000;  // Fixed, not user-supplied

    // Program builds the instruction internally
    let ix = system_instruction::transfer(
        ctx.accounts.pda_treasury.key,
        ctx.accounts.recipient.key,
        REWARD_AMOUNT,  // Hardcoded amount
    );

    invoke_signed(&ix, ..., &[&[b"treasury", &[bump]]])?;
    Ok(())
}
```

---

## Running Tests

```bash
cd anchor
anchor test
```

### Test Coverage

| Test | Description |
|------|-------------|
| `VULNERABILITY: CPI to malicious program` | Demonstrates unchecked program ID |
| `VULNERABILITY: Withdraw from fake vault` | Shows fake PDA substitution |
| `VULNERABILITY: Program signs arbitrary transfer` | Drains PDA with crafted instruction |
| `FIX: Enforces System Program ID` | Typed `Program<'info, T>` prevents substitution |
| `FIX: Works with correct PDA` | Seed constraints enforce derivation |
| `FIX: Program-controlled reward amount` | Hardcoded CPI prevents arbitrary signing |

---

## Key Takeaways

| Vulnerability | Fix | Anchor Pattern |
|---------------|-----|----------------|
| Unchecked Program ID | Validate program identity | `Program<'info, Token>` |
| Unchecked PDA | Enforce canonical derivation | `seeds = [...], bump` |
| Arbitrary CPI Signer | Never sign user-supplied data | Build instruction internally |

### Security Checklist

- [ ] **All CPI targets** use typed `Program<'info, T>` accounts
- [ ] **All PDAs** have `seeds` and `bump` constraints
- [ ] **No `invoke_signed`** with user-controlled instruction data
- [ ] **PDA signing** only for hardcoded, program-controlled operations

---

## Real-World Impact

These vulnerabilities have led to major exploits:

| Protocol | Loss | Vulnerability |
|----------|------|---------------|
| Wormhole | $320M | CPI validation bypass |
| Mango Markets | $116M | Account confusion + CPI |
| Cashio | $28M | Account validation failure |

---

## Anchor vs Pinocchio Comparison

### Anchor Implementation

```rust
// Vulnerable - UncheckedAccount allows any program
#[derive(Accounts)]
pub struct CpiLog<'info> {
    /// CHECK: No validation!
    pub target_program: UncheckedAccount<'info>,
}

// Fixed - Program type enforces ID
#[derive(Accounts)]
pub struct CpiLog<'info> {
    pub target_program: Program<'info, Token>,  // Must be Token Program
}
```

### Pinocchio Implementation

```rust
// Vulnerable - no program ID check
fn process_cpi(accounts: &[AccountInfo]) -> ProgramResult {
    let [target_program, caller] = accounts else { ... };
    
    // BUG: target_program could be any executable
    msg!("Invoking CPI to: {:?}", target_program.key());
    // Proceeds without verification...
}

// Fixed - explicit program ID check
const TOKEN_PROGRAM_ID: Pubkey = pubkey!("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");

fn process_cpi(accounts: &[AccountInfo]) -> ProgramResult {
    let [target_program, caller] = accounts else { ... };
    
    // Verify target program is expected program
    if target_program.key() != &TOKEN_PROGRAM_ID {
        return Err(ProgramError::IncorrectProgramId);
    }
    
    // Also verify account is executable
    if !target_program.is_executable() {
        return Err(ProgramError::InvalidAccountData);
    }
    
    // Now safe to invoke
}
```

### Framework Comparison

| Aspect | Anchor | Pinocchio |
|--------|--------|-----------|
| Program ID check | Implicit via `Program<'info, T>` | Explicit `key() == EXPECTED_ID` |
| PDA verification | `seeds = [...]` constraint | Manual `find_program_address` |
| CPI signing | `CpiContext` with signer seeds | `invoke_signed` with seeds |
| Security model | Type-driven | Explicit checks |

---

## File Structure

```
04-cpi-bugs/
├── README.md
├── anchor/
│   └── programs/
│       ├── 01-unchecked-program-id-vulnerable/
│       ├── 01-unchecked-program-id-fixed/
│       ├── 02-unchecked-pda-vulnerable/
│       ├── 02-unchecked-pda-fixed/
│       ├── 03-arbitrary-cpi-vulnerable/
│       └── 03-arbitrary-cpi-fixed/
└── pinocchio/
    └── programs/
        ├── unchecked-program-id-vulnerable/
        └── unchecked-program-id-fixed/
```

---

## Resources

- [Helius: Hitchhiker's Guide to Solana Security](https://www.helius.dev/blog/a-hitchhikers-guide-to-solana-program-security)
- [Sealevel Attacks - CPI](https://github.com/coral-xyz/sealevel-attacks/tree/master/programs)
- [Anchor Book - PDAs](https://book.anchor-lang.com/anchor_in_depth/PDAs.html)
