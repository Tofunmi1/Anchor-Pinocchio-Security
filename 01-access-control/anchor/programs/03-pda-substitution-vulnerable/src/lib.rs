use anchor_lang::prelude::*;

declare_id!("EydAMcMRg9eTUfBypuXynuWng83vpAqUXhz1uz27UtSz");

/// VULNERABLE: PDA Substitution Attack
/// 
/// This program creates user vaults as PDAs but doesn't verify
/// the PDA seeds during withdrawal. An attacker can pass someone
/// else's vault PDA and drain it.
///
/// PDAs (Program Derived Addresses) are deterministic addresses
/// derived from seeds. If you don't verify the seeds, an attacker
/// can substitute any PDA.

#[program]
pub mod pda_substitution_vulnerable {
    use super::*;

    /// Initialize a user's vault as a PDA
    /// Seeds: ["user_vault", user_pubkey]
    pub fn initialize_vault(ctx: Context<InitializeVault>) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.user = ctx.accounts.user.key();
        vault.balance = 0;
        msg!("Vault initialized for user: {}", vault.user);
        Ok(())
    }

    /// Deposit funds
    pub fn deposit(ctx: Context<DepositVault>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        **ctx.accounts.user.to_account_info().try_borrow_mut_lamports()? -= amount;
        **vault.to_account_info().try_borrow_mut_lamports()? += amount;
        
        vault.balance = vault.balance.checked_add(amount).unwrap();
        msg!("Deposited: {}", amount);
        Ok(())
    }

    /// VULNERABLE: Withdraw without PDA seed verification
    /// 
    /// BUG: We only check that vault.user == user.key()
    /// But we don't verify the vault was derived from the correct seeds!
    /// 
    /// Attack scenario:
    /// 1. Alice has vault at PDA["user_vault", alice_pubkey]
    /// 2. Attacker creates fake vault at arbitrary address
    /// 3. Fake vault has vault.user = attacker_pubkey
    /// 4. Attacker calls withdraw with Alice's vault address
    /// 5. The user field check passes because attacker is signer
    ///    (wait, no - actually the attack is different)
    /// 
    /// Real attack: Missing seeds verification means any account
    /// that deserializes correctly can be passed.
    pub fn withdraw_vulnerable(ctx: Context<WithdrawVulnerable>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        // Check user matches - but is this vault really the user's PDA?
        // BUG: No seeds verification!
        require_keys_eq!(vault.user, ctx.accounts.user.key(), VaultError::Unauthorized);
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
        bump
    )]
    pub vault: Account<'info, UserVault>,
    #[account(mut)]
    pub user: Signer<'info>,
}

#[derive(Accounts)]
pub struct WithdrawVulnerable<'info> {
    // BUG: No seeds constraint!
    // Any Account<UserVault> can be passed, not just the user's PDA
    #[account(mut)]
    pub vault: Account<'info, UserVault>,
    
    #[account(mut)]
    pub user: Signer<'info>,
}

#[account]
#[derive(InitSpace)]
pub struct UserVault {
    pub user: Pubkey,   // 32 bytes
    pub balance: u64,   // 8 bytes
}

#[error_code]
pub enum VaultError {
    #[msg("Unauthorized")]
    Unauthorized,
    #[msg("Insufficient funds")]
    InsufficientFunds,
}
