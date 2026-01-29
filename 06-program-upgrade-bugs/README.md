# Program Upgrade Vulnerabilities

## Overview

Upgradeable programs on Solana can be modified by the upgrade authority. Improper management of this authority leads to critical vulnerabilities.

| # | Vulnerability | Severity | Description |
|---|--------------|----------|-------------|
| 01 | Unprotected Upgrade Authority | Critical | Anyone can change upgrade authority |
| 02 | Missing Authority Verification | Critical | Authority change without proper auth |

---

## Implementations

```
06-program-upgrade-bugs/
├── README.md
├── anchor/
│   └── programs/
│       ├── upgrade-vulnerable/
│       └── upgrade-fixed/
└── pinocchio/
    └── programs/
        ├── upgrade-authority-vulnerable/
        └── upgrade-authority-fixed/
```

---

## Solana Upgradeable Programs

Solana programs can be deployed as upgradeable:

```
┌─────────────────────────────────────────────────────────────────┐
│                    UPGRADEABLE PROGRAM                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Program Account (Executable)                                   │
│  └── Points to Program Data Account                             │
│                                                                 │
│  Program Data Account                                           │
│  ├── upgrade_authority: Pubkey (who can upgrade)                │
│  └── program_bytes: [u8] (the actual code)                      │
│                                                                 │
│  Upgrade Authority can:                                         │
│  - Deploy new code                                              │
│  - Transfer authority to another pubkey                         │
│  - Renounce authority (make immutable)                          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Anchor vs Pinocchio Comparison

### Anchor Implementation

```rust
// Vulnerable - only checks signer, not current authority
pub fn set_authority(ctx: Context<SetAuthority>, new_authority: Pubkey) -> Result<()> {
    // BUG: Doesn't verify caller IS the current authority
    ctx.accounts.program_data.upgrade_authority = new_authority;
    Ok(())
}

// Fixed - has_one constraint verifies authority
#[derive(Accounts)]
pub struct SetAuthority<'info> {
    #[account(
        mut,
        has_one = upgrade_authority @ Error::NotAuthority
    )]
    pub program_data: Account<'info, ProgramData>,
    pub upgrade_authority: Signer<'info>,
}
```

### Pinocchio Implementation

```rust
// Vulnerable - only checks signer
fn process_set_authority(accounts: &[AccountInfo], new_authority: &[u8; 32]) -> ProgramResult {
    let [program_data, caller] = accounts else { ... };

    // BUG: Only checks signer, not that caller IS current authority
    if !caller.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let data = unsafe { program_data.borrow_mut_data_unchecked() };
    data[0..32].copy_from_slice(new_authority);  // Anyone can change!
    Ok(())
}

// Fixed - verifies caller is current authority
fn process_set_authority(accounts: &[AccountInfo], new_authority: &[u8; 32]) -> ProgramResult {
    let [program_data, caller] = accounts else { ... };

    if !caller.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let data = unsafe { program_data.borrow_mut_data_unchecked() };
    
    // Verify caller IS the current authority
    let current_authority = &data[0..32];
    if current_authority != caller.key().as_ref() {
        return Err(ProgramError::InvalidAccountData);
    }

    data[0..32].copy_from_slice(new_authority);
    Ok(())
}
```

### Framework Comparison

| Aspect | Anchor | Pinocchio |
|--------|--------|-----------|
| Authority check | `has_one = upgrade_authority` | Manual pubkey comparison |
| Signer + owner | Combined in constraints | Separate explicit checks |
| Program data access | Typed `Account<'info, ProgramData>` | Raw byte offsets |

---

## Security Best Practices

1. **Always verify current authority**: Check that the caller IS the stored authority
2. **Use multi-sig**: Consider requiring multiple signatures for authority changes
3. **Time-locks**: Implement delays before authority changes take effect
4. **Renounce when ready**: Make programs immutable when development is complete

---

## Running Tests

```bash
cd anchor
anchor test
```

---

## References

- [Solana Program Deployment](https://docs.solana.com/developing/on-chain-programs/deploying)
- [Anchor Program Upgrades](https://book.anchor-lang.com/anchor_in_depth/program_upgrades.html)
