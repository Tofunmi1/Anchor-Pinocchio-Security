use anchor_lang::prelude::*;

declare_id!("jojbHucvseW2LEAnFKGdCLX7PVsdWqVZXQHSAg4GxPq");

/// # Storage Collision - Version 2 (Vulnerable Upgrade)
/// 
/// This program represents a BUGGY upgrade that introduces a storage collision.
/// A new admin privilege system was added, but the developer inserted the
/// `is_admin` field BEFORE `is_active` instead of appending it at the end.
/// 
/// ## Vulnerability: Field Insertion Storage Collision
/// 
/// When a new field is inserted in the middle of a struct, all subsequent
/// fields shift to new offsets. Existing accounts still have data at the
/// original offsets, causing the program to misinterpret stored values.
/// 
/// ## Account Layout Comparison:
/// ```
/// ┌────────────────────────────────────────────────────────────────────────────┐
/// │                    VERSION 1 (Original Layout)                             │
/// ├──────────┬──────┬───────────────┬────────────────────────────────────────────┤
/// │ Offset   │ Size │ Field         │ Value                                      │
/// ├──────────┼──────┼───────────────┼────────────────────────────────────────────┤
/// │ 0-8      │ 8    │ Discriminator │ (Anchor ID)                                │
/// │ 8-16     │ 8    │ balance       │ 1000                                       │
/// │ 16-48    │ 32   │ owner         │ <user_pubkey>                              │
/// │ 48-49    │ 1    │ is_active     │ 0x01 (true)     <-- CRITICAL BYTE          │
/// │ 49+      │ 100  │ (padding)     │ 0x00...                                    │
/// └────────────────────────────────────────────────────────────────────────────┘
///
/// ┌────────────────────────────────────────────────────────────────────────────┐
/// │                    VERSION 2 (Buggy Layout)                                │
/// ├──────────┬──────┬───────────────┬────────────────────────────────────────────┤
/// │ Offset   │ Size │ Field         │ What V2 READS from V1 Data                 │
/// ├──────────┼──────┼───────────────┼────────────────────────────────────────────┤
/// │ 0-8      │ 8    │ Discriminator │ Correct                                    │
/// │ 8-16     │ 8    │ balance       │ 1000 (Correct)                             │
/// │ 16-48    │ 32   │ owner         │ <user_pubkey> (Correct)                    │
/// │ 48-49    │ 1    │ is_admin      │ 0x01 (READS V1's is_active!) -> TRUE!      │
/// │ 49-50    │ 1    │ is_active     │ 0x00 (READS padding) -> FALSE              │
/// └────────────────────────────────────────────────────────────────────────────┘
/// ```
/// 
/// ## Impact:
/// Every V1 user with `is_active = true` is now treated as an admin!
/// This grants unauthorized access to privileged operations like `admin_withdraw`.

#[program]
pub mod storage_collision_v2 {
    use super::*;

    /// Admin-only operation to withdraw funds from any vault.
    /// 
    /// ## Vulnerability
    /// 
    /// This instruction checks `is_admin`, but due to the storage collision,
    /// any V1 account where `is_active = true` will pass this check because
    /// the `is_active` byte is now read as `is_admin`.
    /// 
    /// **Exploit Steps:**
    /// 1. Attacker has a normal V1 vault with `is_active = true`
    /// 2. Attacker calls `admin_withdraw` on V2 program
    /// 3. V2 deserializes vault with new layout
    /// 4. V1's `is_active` (0x01) is read as `is_admin` (true)
    /// 5. Admin check passes -> Unauthorized withdrawal!
    pub fn admin_withdraw(ctx: Context<AdminWithdraw>, amount: u64) -> Result<()> {
        let vault_info = &ctx.accounts.vault;
        let admin = &ctx.accounts.admin;

        // Manual deserialization to read existing V1 account with V2 struct
        let data = vault_info.try_borrow_data()?;
        let mut slice: &[u8] = &data;
        let vault = Vault::try_deserialize(&mut slice)?;
        
        // The bug: is_admin reads the is_active byte from V1 accounts
        require!(vault.is_admin, UpgradeError::NotAdmin);
        
        // Verify sufficient balance
        require!(vault.balance >= amount, UpgradeError::InsufficientBalance);

        // Simulated withdrawal (in production, this would transfer tokens)
        // In a real same-program-ID upgrade, this would succeed and drain funds.
        msg!(
            "VULNERABLE: Admin withdraw {} from vault {} (balance: {})",
            amount,
            vault_info.key(),
            vault.balance
        );

        emit!(AdminWithdrawal {
            vault: vault_info.key(),
            admin: admin.key(),
            amount,
            remaining_balance: vault.balance.saturating_sub(amount),
        });
        
        Ok(())
    }

    /// Emergency pause all operations (admin only).
    /// 
    /// Also vulnerable to the same storage collision exploit.
    pub fn emergency_pause(ctx: Context<AdminWithdraw>) -> Result<()> {
        let vault_info = &ctx.accounts.vault;

        let data = vault_info.try_borrow_data()?;
        let mut slice: &[u8] = &data;
        let vault = Vault::try_deserialize(&mut slice)?;
        
        // Same vulnerability: is_admin check passes for all active V1 users
        require!(vault.is_admin, UpgradeError::NotAdmin);

        msg!("VULNERABLE: Emergency pause by non-admin user");
        
        emit!(EmergencyPaused {
            vault: vault_info.key(),
            paused_by: ctx.accounts.admin.key(),
        });
        
        Ok(())
    }
}

#[derive(Accounts)]
pub struct AdminWithdraw<'info> {
    /// CHECK: We manually deserialize to simulate reading V1 data with V2 layout.
    /// In production, this would be `Account<'info, Vault>`.
    pub vault: UncheckedAccount<'info>,
    
    #[account(mut)]
    pub admin: Signer<'info>,
}

/// Vault account structure (Version 2 - VULNERABLE).
/// 
/// **BUG**: `is_admin` was inserted at offset 48, where V1's `is_active` exists.
/// This causes all active V1 accounts to be treated as admin accounts.
#[account]
pub struct Vault {
    pub balance: u64,      // Offset 8:  8 bytes
    pub owner: Pubkey,     // Offset 16: 32 bytes
    
    // BUG: Inserted here instead of appended at end
    pub is_admin: bool,    // Offset 48: READS V1's is_active (0x01) -> TRUE!
    
    pub is_active: bool,   // Offset 49: READS padding (0x00) -> FALSE
}

// ============================================================================
// Events
// ============================================================================

#[event]
pub struct AdminWithdrawal {
    pub vault: Pubkey,
    pub admin: Pubkey,
    pub amount: u64,
    pub remaining_balance: u64,
}

#[event]
pub struct EmergencyPaused {
    pub vault: Pubkey,
    pub paused_by: Pubkey,
}

// ============================================================================
// Errors
// ============================================================================

#[error_code]
pub enum UpgradeError {
    #[msg("Caller does not have admin privileges.")]
    NotAdmin,
    #[msg("Insufficient balance for withdrawal.")]
    InsufficientBalance,
}
