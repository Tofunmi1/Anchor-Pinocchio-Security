# 06 - Program Upgrade Vulnerabilities

This category covers vulnerabilities that occur when upgrading a Solana program while preserving existing account state. Solana's upgradeable program model allows developers to deploy new versions of their program logic, but existing accounts retain their on-chain data with the original byte layout.

---

## Overview

| Vulnerability | Risk Level | Impact |
|---------------|------------|--------|
| Storage Collision | Critical | Mass privilege escalation, unauthorized access |
| Layout Mismatch | High | Data corruption, incorrect state interpretation |
| Missing Migration | Medium | Inconsistent behavior between old and new accounts |

---

## Challenge: Storage Collision (Field Insertion Bug)

### The Problem

When upgrading a Solana program, you often need to add new fields to existing account structures. If new fields are **inserted in the middle** of a struct (rather than appended at the end), a storage collision occurs because:

1. Existing accounts still have data at the original byte offsets
2. The new struct layout expects fields at different offsets
3. The program misinterprets existing data as new fields

### Real-World Scenario: Token Vault Upgrade

Consider a token vault system that needs to add admin functionality.

**Version 1 (Original):**
```rust
#[account]
pub struct Vault {
    pub balance: u64,      // Offset 8
    pub owner: Pubkey,     // Offset 16
    pub is_active: bool,   // Offset 48 <- Value: 0x01 (true)
}
```

**Version 2 (Buggy - Field Inserted):**
```rust
#[account]
pub struct Vault {
    pub balance: u64,      // Offset 8
    pub owner: Pubkey,     // Offset 16
    pub is_admin: bool,    // Offset 48 <- READS V1's is_active!
    pub is_active: bool,   // Offset 49 <- READS padding (0x00)
}
```

---

## Attack Mechanism

### Byte-Level Visualization

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           STORAGE COLLISION                                     │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  V1 ACCOUNT DATA (created before upgrade):                                      │
│  ┌────────────────────────────────────────────────────────────────────────────┐ │
│  │ Offset:   0        8        16                              48   49        │ │
│  │           ├────────┼────────┼──────────────────────────────┼────┼─────     │ │
│  │ Data:     │ Discr. │balance │          owner               │0x01│ 0x00    │ │
│  │           │        │ (1000) │       (32 bytes)             │    │(padding)│ │
│  │           ├────────┼────────┼──────────────────────────────┼────┼─────     │ │
│  │ V1 reads: │  ---   │balance │          owner               │ is_active    │ │
│  │                                                             │ (true)       │ │
│  └────────────────────────────────────────────────────────────────────────────┘ │
│                                                    ↓                            │
│  V2 STRUCT LAYOUT (buggy upgrade):               COLLISION!                     │
│  ┌────────────────────────────────────────────────────────────────────────────┐ │
│  │ V2 reads: │  ---   │balance │          owner               │is_admin│is_act│ │
│  │           │        │ (1000) │       (32 bytes)             │ TRUE!  │FALSE │ │
│  └────────────────────────────────────────────────────────────────────────────┘ │
│                                                                                 │
│  RESULT: Every active V1 user becomes an admin!                                 │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Exploit Flow

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                          EXPLOIT SEQUENCE                                       │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  1. SETUP (Before Upgrade)                                                      │
│     ┌─────────────────────────────────────────────────────────────────────┐     │
│     │ User creates vault with V1 program:                                 │     │
│     │   - balance: 1000                                                   │     │
│     │   - owner: <user_pubkey>                                            │     │
│     │   - is_active: true (0x01 at byte 48)                               │     │
│     └─────────────────────────────────────────────────────────────────────┘     │
│                                            │                                    │
│                                            ▼                                    │
│  2. UPGRADE (V1 -> V2 with bug)                                                 │
│     ┌─────────────────────────────────────────────────────────────────────┐     │
│     │ Developer deploys V2 with is_admin inserted in middle:              │     │
│     │   - Existing account data unchanged                                 │     │
│     │   - New program logic expects different layout                      │     │
│     └─────────────────────────────────────────────────────────────────────┘     │
│                                            │                                    │
│                                            ▼                                    │
│  3. ATTACK                                                                      │
│     ┌─────────────────────────────────────────────────────────────────────┐     │
│     │ Attacker calls admin_withdraw with their normal user account:       │     │
│     │   - V2 deserializes account with new layout                         │     │
│     │   - V2 reads byte 48 (0x01) as is_admin                             │     │
│     │   - is_admin = true -> Admin check passes!                          │     │
│     │   - Attacker withdraws funds as "admin"                             │     │
│     └─────────────────────────────────────────────────────────────────────┘     │
│                                                                                 │
│  Impact: Every user with is_active=true becomes an admin                        │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## The Fix: Append-Only Field Addition

New fields must ALWAYS be appended to the end of the struct.

**Fixed Version (Field Appended):**
```rust
#[account]
pub struct Vault {
    pub balance: u64,      // Offset 8  (unchanged)
    pub owner: Pubkey,     // Offset 16 (unchanged)
    pub is_active: bool,   // Offset 48 (unchanged) <- Reads 0x01 correctly
    pub is_admin: bool,    // Offset 49 (NEW)       <- Reads padding (0x00) = false
}
```

### Secure Layout Comparison

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                            SECURE UPGRADE                                       │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  V1 ACCOUNT DATA:                                                               │
│  ┌────────────────────────────────────────────────────────────────────────────┐ │
│  │ Offset:   0        8        16                              48   49        │ │
│  │           ├────────┼────────┼──────────────────────────────┼────┼─────     │ │
│  │ Data:     │ Discr. │balance │          owner               │0x01│ 0x00    │ │
│  │           │        │ (1000) │       (32 bytes)             │    │(padding)│ │
│  └────────────────────────────────────────────────────────────────────────────┘ │
│                                                                                 │
│  FIXED STRUCT LAYOUT:                                                           │
│  ┌────────────────────────────────────────────────────────────────────────────┐ │
│  │ Fixed:    │  ---   │balance │          owner               │is_active│is_ad│ │
│  │           │        │ (1000) │       (32 bytes)             │  TRUE   │FALSE│ │
│  └────────────────────────────────────────────────────────────────────────────┘ │
│                                                                ↑                │
│                                               Reads padding = 0 = false (SAFE!) │
│                                                                                 │
│  RESULT: V1 users correctly have is_admin = false                               │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## Code Comparison

### Vulnerable Pattern

```rust
// V2 (VULNERABLE): Field inserted in middle
#[account]
pub struct Vault {
    pub balance: u64,
    pub owner: Pubkey,
    pub is_admin: bool,    // BUG: Inserted here!
    pub is_active: bool,   // Shifted to wrong offset
}

// Attack succeeds: V1's is_active (0x01) read as is_admin (true)
```

### Secure Pattern

```rust
// FIXED: Field appended at end
#[account]
pub struct Vault {
    pub balance: u64,
    pub owner: Pubkey,
    pub is_active: bool,   // Same offset as V1
    pub is_admin: bool,    // NEW: Appended - reads padding (0x00)
}

// Attack fails: is_admin correctly reads as false for V1 accounts
```

---

## Prevention Strategies

| Strategy | Description |
|----------|-------------|
| **Append-Only Fields** | Always add new fields at the end of structs |
| **Version Field** | Add an explicit version number to track struct changes |
| **Pre-allocated Padding** | Reserve space with `#[account(zero_copy)]` or manual padding |
| **Migration Instructions** | Create explicit upgrade paths for existing accounts |
| **Layout Testing** | Test upgrades against real V1 account data before deployment |

### Example: Struct with Version Field

```rust
#[account]
pub struct Vault {
    pub version: u8,       // Always first - track struct version
    pub balance: u64,
    pub owner: Pubkey,
    pub is_active: bool,
    // V2 fields (appended):
    pub is_admin: bool,
    // V3 fields (future):
    pub _reserved: [u8; 64], // Pre-allocated for future upgrades
}
```

---

## Running Tests

```bash
cd anchor
anchor test
```

**Test Coverage:**
1. Creates a V1 vault with `is_active = true`
2. Demonstrates V2 exploit (storage collision grants admin access)
3. Verifies Fixed version correctly rejects unauthorized access
4. Shows raw byte-level account data for analysis

---

## Key Takeaways

1. **Never insert fields in the middle of an existing struct** - this shifts all subsequent field offsets
2. **Always append new fields at the end** - new fields will read zero-initialized padding
3. **Pre-allocate space for upgrades** - reserve extra bytes during initial deployment
4. **Test upgrades with real V1 data** - verify new code correctly interprets existing accounts
5. **Consider explicit migration** - for complex changes, create migration instructions

---

## Related Vulnerabilities

- **Type Confusion** (Module 05): Similar byte-level issues with account discriminators
- **Reinitialization** (Module 03): Improper state management during updates
- **PDA Authority** (Module 04): Upgrade-related CPI authority issues
