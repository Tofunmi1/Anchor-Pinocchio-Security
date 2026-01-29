# Signature Vulnerabilities

## Overview

Signature bugs occur when programs fail to properly verify cryptographic signatures or misuse signature-based authorization.

| # | Vulnerability | Severity | Description |
|---|--------------|----------|-------------|
| 01 | Missing Signature Verification | Critical | Accepting signed messages without verification |
| 02 | Signature Replay | High | Same signature used multiple times |
| 03 | Malleability | Medium | Different signatures for same authorization |

---

## Implementations

```
08-signature-bugs/
├── README.md
├── anchor/
│   └── programs/
│       ├── signature-vulnerable/
│       └── signature-fixed/
└── pinocchio/
    └── programs/
        ├── signature-verification-vulnerable/
        └── signature-verification-fixed/
```

---

## Signer vs Signature

Important distinction on Solana:

| Concept | Description | Check Method |
|---------|-------------|--------------|
| **Signer** | Account that signed the transaction | `is_signer()` flag |
| **Signature** | Off-chain signed message | Ed25519 verification |

- **Signer checks**: Done by the runtime, use `is_signer()`
- **Signature verification**: For off-chain messages, use Ed25519 program

---

## Anchor vs Pinocchio Comparison

### Anchor Implementation

```rust
// Vulnerable - claims to verify but doesn't
pub fn execute_with_signature(
    ctx: Context<Execute>,
    message: Vec<u8>,
    signature: [u8; 64],
) -> Result<()> {
    // BUG: Never actually verifies signature!
    // Just logs and continues
    msg!("Processing message with signature");
    
    // Execute privileged operation without verification
    ctx.accounts.data.value += 1;
    Ok(())
}

// Fixed - uses Ed25519 instruction introspection
pub fn execute_with_signature(
    ctx: Context<Execute>,
    message: Vec<u8>,
    signature: [u8; 64],
) -> Result<()> {
    // Verify Ed25519 instruction exists in transaction
    let ix_sysvar = &ctx.accounts.instruction_sysvar;
    
    // Check that Ed25519 verification passed for this message
    verify_ed25519_signature(
        ix_sysvar,
        &ctx.accounts.signer.key(),
        &message,
        &signature,
    )?;
    
    // Now safe to execute
    ctx.accounts.data.value += 1;
    Ok(())
}
```

### Pinocchio Implementation

```rust
// Vulnerable - never verifies signature
fn process_execute(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let signature = &data[0..64];
    let message = &data[64..];

    // BUG: Never calls ed25519_verify!
    msg!("Processing message (signature not verified!)");
    
    // Executes privileged operation anyway
    Ok(())
}

// Fixed - verifies via Ed25519 program instruction
fn process_execute(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let [signer_pubkey, instructions_sysvar] = accounts else { ... };
    
    let signature = &data[0..64];
    let message = &data[64..];

    // The Ed25519 verification must be in transaction BEFORE this instruction
    // Check Instructions sysvar to verify it passed
    // (Real implementation would parse sysvar and match signature/message/pubkey)
    
    verify_ed25519_in_transaction(
        instructions_sysvar,
        signer_pubkey.key(),
        message,
        signature,
    )?;
    
    msg!("Signature verified - executing");
    Ok(())
}
```

### Framework Comparison

| Aspect | Anchor | Pinocchio |
|--------|--------|-----------|
| Signer check | `Signer<'info>` type | `is_signer()` method |
| Ed25519 verify | Via sysvar introspection | Via sysvar introspection |
| Instruction sysvar | `AccountInfo` passed in | `AccountInfo` passed in |
| Pattern | Same - must use Ed25519 program | Same - must use Ed25519 program |

---

## Ed25519 Verification Pattern

The Solana Ed25519 program verifies signatures:

```
┌─────────────────────────────────────────────────────────────────┐
│                    TRANSACTION FLOW                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Instruction 0: Ed25519Program::verify(pubkey, msg, sig)        │
│                 └── Runtime verifies OR fails transaction       │
│                                                                 │
│  Instruction 1: YourProgram::execute(msg, sig)                  │
│                 └── Check Instructions sysvar                   │
│                 └── Verify Instruction 0 matched our params     │
│                 └── Proceed with operation                      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Replay Prevention

Always include a nonce or timestamp:

```rust
struct SignedMessage {
    nonce: u64,         // Unique per message
    timestamp: i64,     // Prevent stale messages
    action: Action,     // What to do
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

- [Ed25519 Program](https://docs.solana.com/developing/runtime-facilities/programs#ed25519-program)
- [Solana Signature Verification](https://github.com/coral-xyz/sealevel-attacks)
