use anchor_lang::prelude::*;

declare_id!("FwY9MPTdEcpkSBsrCuY3pGYHywvNxTuevbw6F3L1XayD");

/// # Storage Collision - Version 1 (Original Deployment)
/// 
/// This program represents the initial deployment of a token vault system.
/// Users can create vaults with a balance and active status.
/// 
/// ## Account Layout (V1):
/// ```
/// ┌──────────────────────────────────────────────────────────────────────────┐
/// │ Offset │ Size │ Field         │ Type   │ Description                     │
/// ├────────┼──────┼───────────────┼────────┼─────────────────────────────────┤
/// │ 0      │ 8    │ Discriminator │ [u8;8] │ Anchor account type identifier  │
/// │ 8      │ 8    │ balance       │ u64    │ User's token balance            │
/// │ 16     │ 32   │ owner         │ Pubkey │ Account owner's public key      │
/// │ 48     │ 1    │ is_active     │ bool   │ Whether vault is active         │
/// │ 49+    │ 100  │ (padding)     │ -      │ Reserved for future upgrades    │
/// └────────────────────────────────────────────────────────────────────────────┘
/// ```
/// 
/// ## Design Decision: Pre-allocated Padding
/// We allocate an extra 100 bytes beyond the current struct size. This is a 
/// common pattern to allow future upgrades without requiring costly account
/// reallocation. However, if new fields are inserted incorrectly (not appended),
/// this creates the conditions for a storage collision vulnerability.

#[program]
pub mod storage_collision_v1 {
    use super::*;

    /// Creates a new token vault for the user.
    /// 
    /// The vault is initialized with the specified balance and marked as active.
    /// Extra space is pre-allocated to support future upgrades.
    pub fn create_vault(ctx: Context<CreateVault>, initial_balance: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.balance = initial_balance;
        vault.owner = ctx.accounts.owner.key();
        vault.is_active = true;
        
        emit!(VaultCreated {
            vault: vault.key(),
            owner: vault.owner,
            balance: initial_balance,
        });
        
        msg!(
            "Vault created: balance={}, owner={}, is_active=true", 
            initial_balance, 
            vault.owner
        );
        
        Ok(())
    }

    /// Deposits additional tokens into the vault.
    pub fn deposit(ctx: Context<VaultOperation>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        require!(vault.is_active, VaultError::VaultInactive);
        require!(vault.owner == ctx.accounts.owner.key(), VaultError::NotOwner);
        
        vault.balance = vault.balance.checked_add(amount)
            .ok_or(VaultError::Overflow)?;
        
        emit!(Deposited {
            vault: vault.key(),
            amount,
            new_balance: vault.balance,
        });
        
        Ok(())
    }

    /// Withdraws tokens from the vault.
    pub fn withdraw(ctx: Context<VaultOperation>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        require!(vault.is_active, VaultError::VaultInactive);
        require!(vault.owner == ctx.accounts.owner.key(), VaultError::NotOwner);
        require!(vault.balance >= amount, VaultError::InsufficientBalance);
        
        vault.balance = vault.balance.checked_sub(amount)
            .ok_or(VaultError::Underflow)?;
        
        emit!(Withdrawn {
            vault: vault.key(),
            amount,
            new_balance: vault.balance,
        });
        
        Ok(())
    }
}

#[derive(Accounts)]
pub struct CreateVault<'info> {
    /// The vault account to be created.
    /// 
    /// We allocate INIT_SPACE + 100 bytes to reserve room for future fields.
    /// This is where the storage collision vulnerability originates if the
    /// upgrade inserts fields in the wrong position.
    #[account(
        init, 
        payer = owner, 
        space = 8 + Vault::INIT_SPACE + 100 // +100 for future upgrades
    )]
    pub vault: Account<'info, Vault>,
    
    #[account(mut)]
    pub owner: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct VaultOperation<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    
    pub owner: Signer<'info>,
}

/// Token vault account structure (Version 1).
/// 
/// **Critical**: When upgrading, new fields MUST be appended to the end.
/// Inserting fields in the middle will cause storage collision.
#[account]
#[derive(InitSpace)]
pub struct Vault {
    pub balance: u64,      // Offset 8:  8 bytes
    pub owner: Pubkey,     // Offset 16: 32 bytes
    pub is_active: bool,   // Offset 48: 1 byte  -> Value: 0x01 (true)
    // Future fields should be added HERE (after is_active)
}

// ============================================================================
// Events
// ============================================================================

#[event]
pub struct VaultCreated {
    pub vault: Pubkey,
    pub owner: Pubkey,
    pub balance: u64,
}

#[event]
pub struct Deposited {
    pub vault: Pubkey,
    pub amount: u64,
    pub new_balance: u64,
}

#[event]
pub struct Withdrawn {
    pub vault: Pubkey,
    pub amount: u64,
    pub new_balance: u64,
}

// ============================================================================
// Errors
// ============================================================================

#[error_code]
pub enum VaultError {
    #[msg("Vault is not active.")]
    VaultInactive,
    #[msg("Caller is not the vault owner.")]
    NotOwner,
    #[msg("Insufficient balance for withdrawal.")]
    InsufficientBalance,
    #[msg("Arithmetic overflow occurred.")]
    Overflow,
    #[msg("Arithmetic underflow occurred.")]
    Underflow,
}
