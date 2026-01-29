use anchor_lang::prelude::*;

declare_id!("5Pm9fEjr3XcThChsYUfUeejv9q3oFDXARygSPQsLqeqr");

/// FIXED: Proper Owner Check
/// 
/// This program correctly verifies account ownership using Anchor's
/// Account<'info, T> type which automatically checks:
/// 1. Account owner == program_id
/// 2. Account discriminator matches type T
/// 3. Data deserializes correctly

#[program]
pub mod missing_owner_fixed {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.owner = ctx.accounts.owner.key();
        vault.balance = 0;
        vault.is_locked = false;
        msg!("Vault initialized");
        Ok(())
    }

    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        **ctx.accounts.depositor.to_account_info().try_borrow_mut_lamports()? -= amount;
        **vault.to_account_info().try_borrow_mut_lamports()? += amount;
        
        vault.balance = vault.balance.checked_add(amount).unwrap();
        msg!("Deposited: {}", amount);
        Ok(())
    }

    /// FIXED: Withdraw with proper owner verification
    /// 
    /// The vault is now Account<'info, Vault> which means:
    /// - Anchor verifies vault.owner() == program_id (this program)
    /// - Anchor verifies discriminator matches Vault type
    /// - No fake accounts can be passed
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        // This check now works because vault is verified to be real
        require_keys_eq!(vault.owner, ctx.accounts.owner.key(), VaultError::Unauthorized);
        require!(vault.balance >= amount, VaultError::InsufficientFunds);
        
        vault.balance = vault.balance.checked_sub(amount).unwrap();
        
        **vault.to_account_info().try_borrow_mut_lamports()? -= amount;
        **ctx.accounts.owner.try_borrow_mut_lamports()? += amount;
        
        msg!("Withdrew: {}", amount);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = owner,
        space = 8 + Vault::INIT_SPACE,
        seeds = [b"vault", owner.key().as_ref()],
        bump
    )]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub owner: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub depositor: Signer<'info>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    // FIX: Account<'info, Vault> verifies:
    // 1. vault.owner() == this program's ID
    // 2. discriminator == Vault's discriminator
    // 3. data deserializes to Vault struct
    #[account(mut, has_one = owner @ VaultError::Unauthorized)]
    pub vault: Account<'info, Vault>,
    
    #[account(mut)]
    pub owner: Signer<'info>,
}

#[account]
#[derive(InitSpace)]
pub struct Vault {
    pub owner: Pubkey,
    pub balance: u64,
    pub is_locked: bool,
}

#[error_code]
pub enum VaultError {
    #[msg("Unauthorized")]
    Unauthorized,
    #[msg("Insufficient funds")]
    InsufficientFunds,
}
