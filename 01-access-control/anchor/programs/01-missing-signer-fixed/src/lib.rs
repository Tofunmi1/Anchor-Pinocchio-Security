use anchor_lang::prelude::*;

declare_id!("CtRBdgxU8TpJ9jXVJXyPJrRqj9ByXa7M7ixRerVhF1hX");

/// ✅ FIXED VERSION: Proper Signer Verification
/// 
/// This program correctly implements the security pattern where
/// privileged operations require the authority to cryptographically
/// sign the transaction, proving ownership of the private key.
/// 
/// ## Key Differences from Vulnerable Version:
/// 1. `authority` is `Signer<'info>` not `AccountInfo<'info>`
/// 2. Added `has_one = authority` constraint for defense-in-depth
/// 3. Follows Checks-Effects-Interactions pattern

#[program]
pub mod missing_signer_fixed {
    use super::*;

    /// Initialize a new vault for the authority
    /// 
    /// ## Account Model:
    /// - Creates a PDA owned by this program
    /// - Stores the authority pubkey for future authorization checks
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.authority = ctx.accounts.authority.key();
        vault.balance = 0;
        msg!("Vault initialized for: {}", vault.authority);
        Ok(())
    }

    /// Deposit lamports into the vault
    /// 
    /// ## State Mutation Safety:
    /// - Uses checked_add to prevent overflow
    /// - Updates state after successful transfer
    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        // Transfer lamports from depositor to vault
        let ix = anchor_lang::solana_program::system_instruction::transfer(
            &ctx.accounts.depositor.key(),
            &vault.key(),
            amount,
        );
        anchor_lang::solana_program::program::invoke(
            &ix,
            &[
                ctx.accounts.depositor.to_account_info(),
                vault.to_account_info(),
            ],
        )?;
        
        // Safe arithmetic - prevents overflow
        vault.balance = vault.balance
            .checked_add(amount)
            .ok_or(VaultError::Overflow)?;
        
        msg!("Deposited: {}. New balance: {}", amount, vault.balance);
        Ok(())
    }

    /// ✅ SECURE: Withdraw with proper signer verification
    /// 
    /// ## Security Model:
    /// 1. Anchor verifies `authority.is_signer == true` (via Signer type)
    /// 2. `has_one` verifies `vault.authority == authority.key()`
    /// 3. Balance check prevents overdraw
    /// 4. Checked arithmetic prevents underflow
    /// 
    /// ## Why This Is Secure:
    /// An attacker cannot call this function on someone else's vault because:
    /// - They would need the victim's private key to sign
    /// - Without the signature, the transaction is rejected
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        // CHECK: Sufficient balance
        require!(vault.balance >= amount, VaultError::InsufficientFunds);
        
        // EFFECT: Update state BEFORE external lamport transfer
        // This follows the Checks-Effects-Interactions pattern
        vault.balance = vault.balance
            .checked_sub(amount)
            .ok_or(VaultError::Underflow)?;
        
        // INTERACTION: Transfer lamports
        **vault.to_account_info().try_borrow_mut_lamports()? -= amount;
        **ctx.accounts.authority.try_borrow_mut_lamports()? += amount;
        
        msg!("Withdrew: {}. Remaining: {}", amount, vault.balance);
        Ok(())
    }
}

/// Initialize accounts - creates the vault PDA
#[derive(Accounts)]
pub struct Initialize<'info> {
    /// The vault account - a PDA owned by this program
    /// 
    /// Seeds include authority pubkey to ensure one vault per user
    #[account(
        init,
        payer = authority,
        space = 8 + Vault::INIT_SPACE,
        seeds = [b"vault", authority.key().as_ref()],
        bump
    )]
    pub vault: Account<'info, Vault>,
    
    /// The authority who will own this vault
    /// Must sign to pay for account creation
    #[account(mut)]
    pub authority: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

/// Deposit accounts
#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    
    /// Depositor must sign to authorize the transfer
    #[account(mut)]
    pub depositor: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

/// ✅ FIXED: Withdraw accounts with proper security
#[derive(Accounts)]
pub struct Withdraw<'info> {
    /// The vault with dual verification:
    /// 1. `has_one = authority` - ensures vault.authority == authority.key()
    /// 2. Account type ensures proper ownership
    #[account(
        mut,
        has_one = authority @ VaultError::Unauthorized
    )]
    pub vault: Account<'info, Vault>,
    
    /// ✅ THE FIX: Changed from AccountInfo to Signer
    /// 
    /// Anchor generates this check:
    /// ```
    /// if !authority.is_signer {
    ///     return Err(ErrorCode::ConstraintSigner.into());
    /// }
    /// ```
    /// 
    /// This means the authority's private key MUST have signed this transaction
    #[account(mut)]
    pub authority: Signer<'info>,
}

/// Vault account data structure
#[account]
#[derive(InitSpace)]
pub struct Vault {
    /// The pubkey authorized to withdraw from this vault
    pub authority: Pubkey,  // 32 bytes
    
    /// Current balance in lamports
    pub balance: u64,       // 8 bytes
}

#[error_code]
pub enum VaultError {
    #[msg("Unauthorized: you don't own this vault")]
    Unauthorized,
    
    #[msg("Insufficient funds in vault")]
    InsufficientFunds,
    
    #[msg("Arithmetic overflow")]
    Overflow,
    
    #[msg("Arithmetic underflow")]
    Underflow,
}
