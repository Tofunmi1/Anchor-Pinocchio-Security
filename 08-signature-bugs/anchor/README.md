# 08 - Signature Verification Vulnerabilities

This category covers vulnerabilities where programs fail to verify that required accounts have actually **signed** the transaction. Simply matching a public key is not enough - the signature must be validated.

---

## Overview

| Vulnerability | Risk Level | Impact |
|---------------|------------|--------|
| Missing Signer Check | Critical | Full account takeover, fund theft |
| Ed25519 Introspection Bypass | High | Off-chain signature authorization bypass |

---

## Key Concept: Address vs Signature Verification

Solana transactions can include accounts in two ways:

| Type | Signature Required | Use Case |
|------|-------------------|----------|
| **Signer** | Yes - private key signs | Authorization, ownership proof |
| **Non-Signer** | No - just a reference | Read-only access, data lookup |

The critical distinction:
- **Address Check**: `account_a.key() == expected_pubkey` - Anyone can pass any pubkey
- **Signature Check**: Account marked as signer AND valid signature - Only private key holder

---

## Challenge 1: Missing Signer Check

### The Problem

A common vulnerability pattern:

```rust
// The program checks if the authority ADDRESS matches the owner
require_keys_eq!(vault.owner, authority.key(), Error::InvalidOwner);

// But NEVER checks if authority actually SIGNED!
// Missing: require!(authority.is_signer, Error::MissingSignature);
```

### Attack Mechanism

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                       MISSING SIGNER CHECK EXPLOIT                              │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  SETUP:                                                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐        │
│  │  Vault Account (on-chain, public data):                            │        │
│  │    owner: 0xABC123...  (legitimate owner's pubkey)                 │        │
│  │    balance: 1000 SOL                                               │        │
│  └─────────────────────────────────────────────────────────────────────┘        │
│                                                                                 │
│  ATTACK:                                                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐        │
│  │  Attacker builds transaction:                                      │        │
│  │                                                                    │        │
│  │  Instruction: update_owner(new_owner = ATTACKER_PUBKEY)            │        │
│  │                                                                    │        │
│  │  Accounts:                                                         │        │
│  │    - vault: [vault PDA]                                            │        │
│  │    - authority: 0xABC123... (owner's pubkey, NOT signing)          │        │
│  │                                                                    │        │
│  │  Signers:                                                          │        │
│  │    - ATTACKER (only to pay gas fees)                               │        │
│  │                                                                    │        │
│  │  What program checks:                                              │        │
│  │    vault.owner == authority.key()  -->  TRUE (addresses match)     │        │
│  │                                                                    │        │
│  │  What program SHOULD check:                                        │        │
│  │    authority.is_signer == true     -->  FALSE (never checked!)     │        │
│  └─────────────────────────────────────────────────────────────────────┘        │
│                                                                                 │
│  RESULT: Ownership transferred to attacker without owner's consent!            │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Code Comparison

**Vulnerable Pattern:**
```rust
#[derive(Accounts)]
pub struct UpdateOwner<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    
    /// CHECK: VULNERABILITY - This should be Signer<'info>
    /// Anyone can pass any pubkey without proving ownership
    pub authority: UncheckedAccount<'info>,
}

pub fn update_owner(ctx: Context<UpdateOwner>, new_owner: Pubkey) -> Result<()> {
    // Only checks ADDRESS - not SIGNATURE!
    require_keys_eq!(vault.owner, authority.key(), Error::InvalidOwner);
    vault.owner = new_owner;
    Ok(())
}
```

**Secure Pattern:**
```rust
#[derive(Accounts)]
pub struct UpdateOwner<'info> {
    #[account(
        mut, 
        constraint = vault.owner == authority.key() @ Error::InvalidOwner
    )]
    pub vault: Account<'info, Vault>,
    
    // SECURE: Signer<'info> enforces signature verification
    // Transaction fails if authority doesn't sign
    pub authority: Signer<'info>,
}

pub fn update_owner(ctx: Context<UpdateOwner>, new_owner: Pubkey) -> Result<()> {
    // No need to check is_signer - Anchor does it automatically!
    vault.owner = new_owner;
    Ok(())
}
```

---

## Challenge 2: Ed25519 Introspection Bypass

### The Problem

Some programs need to verify off-chain signatures (e.g., for gasless transactions or oracle data). Solana provides the Ed25519 native program for this. Programs can check if an Ed25519 verification instruction exists in the same transaction.

**The vulnerability**: Only checking that an Ed25519 instruction EXISTS, without verifying:
- The correct public key was used
- The correct message was signed
- The signature actually succeeded

### Attack Mechanism

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    ED25519 INTROSPECTION BYPASS                                 │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  VULNERABLE CHECK:                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐        │
│  │  // Only checks if Ed25519 program was invoked                     │        │
│  │  for each instruction in transaction:                              │        │
│  │      if instruction.program_id == Ed25519_PROGRAM_ID:              │        │
│  │          found_ed25519 = true  // BAD: No content validation!      │        │
│  │                                                                    │        │
│  │  require!(found_ed25519, Error::MissingSignature);                 │        │
│  └─────────────────────────────────────────────────────────────────────┘        │
│                                                                                 │
│  ATTACK:                                                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐        │
│  │  Transaction with two instructions:                                │        │
│  │                                                                    │        │
│  │  1. Ed25519 Verify Instruction:                                    │        │
│  │     - pubkey: ATTACKER_KEY (not authority!)                        │        │
│  │     - message: "Hello world" (not authorization!)                  │        │
│  │     - signature: [valid signature for above]                       │        │
│  │                                                                    │        │
│  │  2. claim_reward Instruction:                                      │        │
│  │     - Program finds Ed25519 instruction --> CHECK PASSES           │        │
│  │     - Program never validates WHAT was signed                      │        │
│  │     - Attacker claims reward without authorization!                │        │
│  └─────────────────────────────────────────────────────────────────────┘        │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Secure Pattern

```rust
pub fn claim_reward(ctx: Context<ClaimReward>) -> Result<()> {
    // Find Ed25519 instruction
    for ix in transaction_instructions {
        if ix.program_id == Ed25519_PROGRAM_ID {
            // Parse the Ed25519 instruction data
            let ix_pubkey = parse_pubkey_from_ed25519_ix(&ix.data);
            let ix_message = parse_message_from_ed25519_ix(&ix.data);
            
            // SECURE: Verify the pubkey matches expected authority
            require!(ix_pubkey == reward.authority, Error::WrongSigner);
            
            // SECURE: Verify the message is a valid claim authorization
            let expected = format!("CLAIM:{}:{}", reward.key(), reward.nonce);
            require!(ix_message == expected.as_bytes(), Error::WrongMessage);
            
            return Ok(()); // Only if both checks pass
        }
    }
    Err(Error::MissingSignature)
}
```

---

## Programs in This Module

| Program | Description |
|---------|-------------|
| `01-signature-vulnerable` | Uses `UncheckedAccount` for authority - missing signer check |
| `01-signature-fixed` | Uses `Signer<'info>` for proper signature enforcement |
| `02-introspection-vulnerable` | Only checks Ed25519 instruction exists, not content |
| `02-introspection-fixed` | Validates pubkey and message in Ed25519 instruction |

---

## Running Tests

```bash
cd anchor
anchor test
```

**Test Coverage:**
- Demonstrates ownership hijacking without private key
- Shows fund withdrawal after hijacking
- Verifies fixed version rejects unsigned transactions
- Confirms legitimate signed operations work correctly

---

## Prevention Checklist

| Check | How to Implement |
|-------|------------------|
| Require signer for owner operations | Use `Signer<'info>` type in Anchor |
| Validate signer in native programs | Check `AccountInfo.is_signer == true` |
| Ed25519: Verify public key | Parse Ed25519 ix data, compare pubkey |
| Ed25519: Verify message | Parse Ed25519 ix data, compare message content |
| Ed25519: Use nonce | Prevent replay attacks with unique claim IDs |

---

## Key Takeaways

1. **Address matching is NOT authorization** - Anyone can reference any public key
2. **Always use `Signer<'info>`** - Anchor automatically enforces signature verification
3. **Ed25519 introspection needs full validation** - Check pubkey AND message content
4. **Defense in depth** - Combine multiple checks (address + signature + constraints)
5. **Test attack scenarios** - Verify your program rejects unsigned impersonation attempts

---

## Related Vulnerabilities

- **Type Confusion** (Module 05): Similar concept of trusting unchecked account data
- **CPI Authority** (Module 04): Bypassing authority through cross-program calls
- **Missing Owner Check** (Module 02): Related account validation issues
