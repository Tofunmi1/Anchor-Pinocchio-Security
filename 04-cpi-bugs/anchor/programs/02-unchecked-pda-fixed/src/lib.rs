use anchor_lang::prelude::*;

declare_id!("AAdZNcYNd2LmcU3J8gbYjazPVKJ9T5zd1evJJPirnZbu");

/// # Secure: Checked PDA Derivation
/// 
/// This program ensures that the vault account is derived from deterministic
/// seeds, preventing account substitution attacks.

#[program]
pub mod unchecked_pda_fixed {
    use super::*;

    /// Creates a new vault for the authority using PDA seeds.
    pub fn initialize_vault(ctx: Context<InitializeVault>) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.amount = 100;
        vault.owner = ctx.accounts.authority.key();
        
        emit!(VaultInitialized {
            vault: vault.key(),
            owner: vault.owner,
            amount: vault.amount,
        });
        
        Ok(())
    }

    /// Withdraws funds from the authority's vault.
    /// 
    /// ## Secure Pattern: PDA Seed Constraint
    /// 
    /// The `vault` account is constrained by `seeds = [b"vault", authority.key()]`.
    /// Anchor verifies that the account address matches the derived PDA.
    /// An attacker cannot substitute a fake vault because the address would
    /// not match the expected derivation.
    pub fn withdraw(ctx: Context<Withdraw>) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        require!(vault.owner == ctx.accounts.authority.key(), VaultError::NotOwner);
        require!(vault.amount > 0, VaultError::Empty);
        
        let withdrawn = vault.amount;
        vault.amount = 0;
        
        emit!(Withdrawal {
            vault: vault.key(),
            authority: ctx.accounts.authority.key(),
            amount: withdrawn,
        });
        
        msg!("Withdraw successful from verified vault: {}", vault.key());
        Ok(())
    }
}

#[derive(Accounts)]
pub struct InitializeVault<'info> {
    #[account(
        init, 
        payer = authority, 
        space = 8 + Vault::INIT_SPACE,
        seeds = [b"vault", authority.key().as_ref()], // Secure: Deterministic PDA
        bump
    )]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(
        mut,
        seeds = [b"vault", authority.key().as_ref()], // Secure: Verifies canonical PDA
        bump,
        constraint = vault.owner == authority.key() @ VaultError::NotOwner
    )]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}

#[account]
#[derive(InitSpace)]
pub struct Vault {
    pub amount: u64,
    pub owner: Pubkey,
}

#[event]
pub struct VaultInitialized {
    pub vault: Pubkey,
    pub owner: Pubkey,
    pub amount: u64,
}

#[event]
pub struct Withdrawal {
    pub vault: Pubkey,
    pub authority: Pubkey,
    pub amount: u64,
}

#[error_code]
pub enum VaultError {
    #[msg("Caller is not the vault owner.")]
    NotOwner,
    #[msg("Vault is empty.")]
    Empty,
}
