use anchor_lang::prelude::*;

declare_id!("EvEETfCxZpVUqxeTJdRHdVtAX8MtnM98uVychPuHJERT");

/// # Storage Collision - Fixed Version (Safe Upgrade)
/// 
/// This program demonstrates the CORRECT way to add new fields during an upgrade.
/// New fields are APPENDED to the end of the struct, preserving backward compatibility.
/// 
/// ## Secure Pattern: Append-Only Field Addition
/// 
/// When adding new fields to an existing account structure:
/// 1. ALWAYS add new fields at the END of the struct
/// 2. NEVER insert fields in the middle or change field order
/// 3. Consider using explicit version fields for complex migrations
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
/// │ 48-49    │ 1    │ is_active     │ 0x01 (true)                                │
/// │ 49+      │ 100  │ (padding)     │ 0x00...                                    │
/// └────────────────────────────────────────────────────────────────────────────┘
///
/// ┌────────────────────────────────────────────────────────────────────────────┐
/// │                    FIXED VERSION (Safe Layout)                             │
/// ├──────────┬──────┬───────────────┬────────────────────────────────────────────┤
/// │ Offset   │ Size │ Field         │ What FIXED reads from V1 Data              │
/// ├──────────┼──────┼───────────────┼────────────────────────────────────────────┤
/// │ 0-8      │ 8    │ Discriminator │ Correct                                    │
/// │ 8-16     │ 8    │ balance       │ 1000 (Correct)                             │
/// │ 16-48    │ 32   │ owner         │ <user_pubkey> (Correct)                    │
/// │ 48-49    │ 1    │ is_active     │ 0x01 (Correct - same offset as V1)         │
/// │ 49-50    │ 1    │ is_admin      │ 0x00 (READS padding) -> FALSE (SAFE!)      │
/// └────────────────────────────────────────────────────────────────────────────┘
/// ```
/// 
/// ## Why This Works:
/// By appending `is_admin` at offset 49 (AFTER `is_active`), we read into the
/// pre-allocated padding bytes which are all zeros. This means:
/// - All existing V1 accounts correctly read `is_admin = false`
/// - Only newly created or explicitly migrated accounts can be admins
/// - Backward compatibility is preserved

#[program]
pub mod storage_collision_fixed {
    use super::*;

    /// Admin-only operation to withdraw funds from any vault.
    /// 
    /// ## Secure Implementation
    /// 
    /// With the correct struct layout, the `is_admin` field reads from
    /// padding bytes (offset 49) which are guaranteed to be 0x00 for V1 accounts.
    /// This means no V1 user can gain admin privileges through storage collision.
    pub fn admin_withdraw(ctx: Context<AdminWithdraw>, amount: u64) -> Result<()> {
        let vault_info = &ctx.accounts.vault;
        let admin = &ctx.accounts.admin;

        // Deserialize with FIXED layout
        let data = vault_info.try_borrow_data()?;
        let mut slice: &[u8] = &data;
        let vault = Vault::try_deserialize(&mut slice)?;
        
        // SAFE: is_admin reads from padding (0x00) for V1 accounts
        require!(vault.is_admin, UpgradeError::NotAdmin);
        
        require!(vault.balance >= amount, UpgradeError::InsufficientBalance);

        msg!(
            "SECURE: Admin withdraw {} from vault {} (balance: {})",
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

    /// Grants admin privileges to a vault (must be called by current admin).
    /// 
    /// This demonstrates how to safely promote users to admin status
    /// after the upgrade, without relying on storage collision.
    pub fn grant_admin(ctx: Context<AdminOperation>) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        let grantor = &ctx.accounts.admin;
        
        // In production, you would verify grantor is an existing admin
        // For this example, we just set the flag
        vault.is_admin = true;
        
        emit!(AdminGranted {
            vault: vault.key(),
            granted_by: grantor.key(),
        });
        
        msg!("Admin privileges granted to vault: {}", vault.key());
        
        Ok(())
    }

    /// Revokes admin privileges from a vault.
    pub fn revoke_admin(ctx: Context<AdminOperation>) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        vault.is_admin = false;
        
        emit!(AdminRevoked {
            vault: vault.key(),
            revoked_by: ctx.accounts.admin.key(),
        });
        
        msg!("Admin privileges revoked from vault: {}", vault.key());
        
        Ok(())
    }
}

#[derive(Accounts)]
pub struct AdminWithdraw<'info> {
    /// CHECK: Manual deserialization to demonstrate the fix.
    pub vault: UncheckedAccount<'info>,
    
    #[account(mut)]
    pub admin: Signer<'info>,
}

#[derive(Accounts)]
pub struct AdminOperation<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    
    pub admin: Signer<'info>,
}

/// Vault account structure (Fixed Version).
/// 
/// **CORRECT**: `is_admin` is APPENDED at the end, not inserted in the middle.
/// This ensures backward compatibility with V1 accounts.
#[account]
pub struct Vault {
    pub balance: u64,      // Offset 8:  8 bytes
    pub owner: Pubkey,     // Offset 16: 32 bytes
    pub is_active: bool,   // Offset 48: 1 byte (SAME as V1 - preserved!)
    
    // CORRECT: Appended at end - reads padding (0x00) for V1 accounts
    pub is_admin: bool,    // Offset 49: Reads 0x00 -> FALSE (safe default)
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
pub struct AdminGranted {
    pub vault: Pubkey,
    pub granted_by: Pubkey,
}

#[event]
pub struct AdminRevoked {
    pub vault: Pubkey,
    pub revoked_by: Pubkey,
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
