use anchor_lang::prelude::*;

declare_id!("13zVgMdotKjDGK9Gznow7t621HMLgMBWDmWdikn5jon4");

/// FIXED: PDA Substitution Prevention
/// 
/// This program correctly verifies PDA seeds on every operation.
/// The seeds constraint ensures the vault address is deterministically
/// derived from the expected seeds, preventing account substitution.

#[program]
pub mod pda_substitution_fixed {
    use super::*;

    pub fn initialize_vault(ctx: Context<InitializeVault>) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.user = ctx.accounts.user.key();
        vault.balance = 0;
        vault.bump = ctx.bumps.vault;  // Store bump for future verification
        msg!("Vault initialized for user: {}", vault.user);
        Ok(())
    }

    pub fn deposit(ctx: Context<DepositVault>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        **ctx.accounts.user.to_account_info().try_borrow_mut_lamports()? -= amount;
        **vault.to_account_info().try_borrow_mut_lamports()? += amount;
        
        vault.balance = vault.balance.checked_add(amount).unwrap();
        msg!("Deposited: {}", amount);
        Ok(())
    }

    /// FIXED: Withdraw with PDA seed verification
    /// 
    /// The seeds constraint on vault ensures:
    /// 1. vault address == PDA(["user_vault", user.key()], program_id)
    /// 2. Only the vault belonging to this specific user can be passed
    /// 3. No account substitution is possible
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        require!(vault.balance >= amount, VaultError::InsufficientFunds);
        
        vault.balance = vault.balance.checked_sub(amount).unwrap();
        
        **vault.to_account_info().try_borrow_mut_lamports()? -= amount;
        **ctx.accounts.user.try_borrow_mut_lamports()? += amount;
        
        msg!("Withdrew: {}", amount);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct InitializeVault<'info> {
    #[account(
        init,
        payer = user,
        space = 8 + UserVault::INIT_SPACE,
        seeds = [b"user_vault", user.key().as_ref()],
        bump
    )]
    pub vault: Account<'info, UserVault>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct DepositVault<'info> {
    #[account(
        mut,
        seeds = [b"user_vault", user.key().as_ref()],
        bump = vault.bump
    )]
    pub vault: Account<'info, UserVault>,
    #[account(mut)]
    pub user: Signer<'info>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    // FIX: Seeds constraint verifies this is exactly the user's vault PDA
    // 
    // Anchor computes: expected_address = PDA(["user_vault", user.key()], program_id)
    // Then verifies: vault.key() == expected_address
    // 
    // If attacker tries to pass a different vault, the seeds won't match
    // and Anchor returns ConstraintSeeds error
    #[account(
        mut,
        seeds = [b"user_vault", user.key().as_ref()],
        bump = vault.bump,
        has_one = user @ VaultError::Unauthorized
    )]
    pub vault: Account<'info, UserVault>,
    
    #[account(mut)]
    pub user: Signer<'info>,
}

#[account]
#[derive(InitSpace)]
pub struct UserVault {
    pub user: Pubkey,   // 32 bytes
    pub balance: u64,   // 8 bytes
    pub bump: u8,       // 1 byte - store for efficient verification
}

#[error_code]
pub enum VaultError {
    #[msg("Unauthorized")]
    Unauthorized,
    #[msg("Insufficient funds")]
    InsufficientFunds,
}
