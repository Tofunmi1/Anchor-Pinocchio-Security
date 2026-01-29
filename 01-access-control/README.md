# Access Control Vulnerabilities

## Overview

Access control bugs occur when programs fail to properly verify who is authorized 
to perform an action. These are the most common and devastating bugs in Solana programs.

| # | Vulnerability | Severity | Real-world Example |
|---|--------------|----------|-------------------|
| 01 | Missing Signer Check | Critical | Wormhole ($320M) |
| 02 | Missing Owner Check | Critical | Cashio ($52M) |
| 03 | PDA Substitution | High | Multiple DeFi protocols |

---

## Implementations

This module includes both Anchor and Pinocchio implementations to demonstrate the same vulnerabilities across different frameworks.

```
01-access-control/
├── README.md
├── anchor/                    # Anchor framework implementation
│   └── programs/
│       ├── 01-missing-signer-vulnerable/
│       ├── 01-missing-signer-fixed/
│       ├── 02-missing-owner-vulnerable/
│       ├── 02-missing-owner-fixed/
│       ├── 03-pda-substitution-vulnerable/
│       └── 03-pda-substitution-fixed/
└── pinocchio/                 # Pinocchio framework implementation
    └── programs/
        ├── missing-signer-vulnerable/
        └── missing-signer-fixed/
```

---

## Solana Account Model

Every transaction includes accounts and signatures:

```
Transaction {
    signatures: [sig1, sig2, ...],     // Proofs of authorization
    message: {
        accounts: [acc1, acc2, ...],   // Accounts referenced
        instructions: [...]
    }
}
```

| Concept | What It Means |
|---------|---------------|
| Account | Any Solana account - pubkeys are public |
| Signer | Account whose private key signed the tx |
| Owner | Program that controls the account's data |
| PDA | Deterministic address derived from seeds |

---

## 01 - Missing Signer Check

### The Bug

The program checks that an authority pubkey matches the stored value, but does not verify that the authority actually signed the transaction.

### Why It Happens

Pubkeys are public information. Just because a pubkey is passed as an account does not mean the owner authorized the action. The `is_signer` flag proves private key ownership - the Solana runtime sets this flag only after verifying an Ed25519 signature from the corresponding private key.

---

## Anchor vs Pinocchio Comparison

### Anchor Implementation

Anchor uses a type-driven approach where security checks are implicit in the account types:

```rust
// VULNERABLE - AccountInfo does not require signature
#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// CHECK: VULNERABLE - Not checking if this account signed
    #[account(mut)]
    pub authority: AccountInfo<'info>,  // Anyone can pass any pubkey
}

// FIXED - Signer type enforces is_signer check
#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut, has_one = authority)]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub authority: Signer<'info>,  // Must have signed the transaction
}
```

**How Anchor Protects You:**
- `Signer<'info>` automatically generates: `if !account.is_signer { return Err(...) }`
- `Account<'info, T>` verifies owner and deserializes typed data
- `has_one = authority` verifies stored pubkey matches passed account

### Pinocchio Implementation

Pinocchio uses explicit checks - you must manually verify everything:

```rust
// VULNERABLE - Missing is_signer() check
fn process_withdraw(accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    let [vault, authority] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    let vault_data = unsafe { vault.borrow_mut_data_unchecked() };
    let stored_authority = &vault_data[0..32];

    // Only checks pubkey match - NOT if they signed!
    if stored_authority != authority.key().as_ref() {
        return Err(ProgramError::InvalidAccountData);
    }

    // Missing: if !authority.is_signer() { return Err(...) }

    // Proceeds to withdraw...
}

// FIXED - Explicit is_signer() check added
fn process_withdraw(accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    let [vault, authority] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // THE FIX: Verify signature first
    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let vault_data = unsafe { vault.borrow_mut_data_unchecked() };
    let stored_authority = &vault_data[0..32];

    if stored_authority != authority.key().as_ref() {
        return Err(ProgramError::InvalidAccountData);
    }

    // Now safe to withdraw
}
```

---

## Framework Comparison Table

| Aspect | Anchor | Pinocchio |
|--------|--------|-----------|
| **Signer Check** | Implicit via `Signer<'info>` type | Explicit `is_signer()` call required |
| **Owner Check** | Implicit via `Account<'info, T>` | Explicit `owner()` comparison required |
| **Account Parsing** | Automatic via `#[derive(Accounts)]` | Manual array destructuring |
| **Data Access** | Type-safe: `vault.balance` | Raw bytes: `data[32..40]` |
| **Error Handling** | Custom `#[error_code]` enums | Standard `ProgramError` variants |
| **Memory Model** | Borsh serialization | Zero-copy direct memory access |
| **Binary Size** | Larger (more abstractions) | Smaller (minimal overhead) |
| **Compute Cost** | Higher (deserialization) | Lower (zero-copy) |

### Security Trade-offs

| Framework | Pros | Cons |
|-----------|------|------|
| **Anchor** | Type system catches bugs at compile time; Harder to forget checks | Abstraction can hide what checks are actually happening |
| **Pinocchio** | Full visibility into all checks; Maximum performance | Must remember every check manually; Easy to forget one |

---

## 02 - Missing Owner Check

### The Bug

```rust
// VULNERABLE - accepts any account regardless of owner
pub vault: UncheckedAccount<'info>,

// FIXED - must be owned by this program  
pub vault: Account<'info, Vault>,
```

### Why It Happens

Every account has an `owner` field indicating which program can modify its data. Without verification, attackers can create fake accounts with crafted data that your program trusts.

### Anchor Protection

`Account<'info, T>` verifies:
1. `account.owner == program_id`
2. Discriminator matches type T
3. Data deserializes correctly

### Pinocchio Equivalent

```rust
// Must check owner manually
if vault.owner() != program_id {
    return Err(ProgramError::IncorrectProgramId);
}
```

---

## 03 - PDA Substitution

### The Bug

```rust
// VULNERABLE - no seeds verification
#[account(mut)]
pub vault: Account<'info, UserVault>,

// FIXED - seeds verified
#[account(
    mut,
    seeds = [b"user_vault", user.key().as_ref()],
    bump = vault.bump
)]
pub vault: Account<'info, UserVault>,
```

### Why It Happens

PDAs are deterministic but you must verify the seeds match. Without seeds constraints, an attacker could substitute a different PDA that they control.

---

## Defense in Depth

Combine multiple access control checks:

```rust
// Anchor - Multiple implicit checks
#[derive(Accounts)]
pub struct SecureWithdraw<'info> {
    #[account(
        mut,
        seeds = [b"vault", authority.key().as_ref()],  // PDA seeds
        bump = vault.bump,
        has_one = authority                             // Stored pubkey
    )]
    pub vault: Account<'info, Vault>,  // Owner + discriminator
    
    pub authority: Signer<'info>,      // Signature required
}

// Pinocchio - All checks explicit
fn secure_withdraw(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let [vault, authority] = accounts else { ... };

    // 1. Signer check
    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // 2. Owner check
    if vault.owner() != program_id {
        return Err(ProgramError::IncorrectProgramId);
    }

    // 3. PDA derivation check
    let (expected_pda, _) = Pubkey::find_program_address(
        &[b"vault", authority.key().as_ref()],
        program_id,
    );
    if vault.key() != &expected_pda {
        return Err(ProgramError::InvalidSeeds);
    }

    // 4. Stored authority check
    let stored_authority = &vault_data[0..32];
    if stored_authority != authority.key().as_ref() {
        return Err(ProgramError::InvalidAccountData);
    }

    // All checks passed - safe to proceed
}
```

---

## Anchor Constraints Reference

| Constraint | Purpose |
|------------|---------|
| `Signer<'info>` | Require signature |
| `Account<'info, T>` | Verify owner + type |
| `has_one = field` | Verify stored pubkey matches |
| `seeds = [...]` | Verify PDA derivation |
| `owner = program` | Verify specific owner |
| `constraint = expr` | Custom boolean check |

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
cargo build-sbf --release  # For on-chain deployment
```

---

## References

- Sealevel Attacks: https://github.com/coral-xyz/sealevel-attacks
- Anchor Constraints: https://www.anchor-lang.com/docs/account-constraints
- Pinocchio: https://github.com/febo/pinocchio
