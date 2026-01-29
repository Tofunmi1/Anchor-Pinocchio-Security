use anchor_lang::prelude::*;

declare_id!("BH5HWxfnGHa81jEBZXdt6zFh5TZpVMsiVEqDCE23YBW");

/// ⚠️ VULNERABLE: Missing Signer Check
/// 
/// This program allows anyone to withdraw from any vault because
/// the authority account is NOT required to sign the transaction.

#[program]
pub mod missing_signer_vulnerable {
    use super::*;

    /// Initialize a new vault for the authority
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.authority = ctx.accounts.authority.key();
        vault.balance = 0;
        msg!("Vault initialized for: {}", vault.authority);
        Ok(())
    }

    /// Deposit lamports into the vault
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
        
        vault.balance = vault.balance.checked_add(amount).unwrap();
        msg!("Deposited: {}. New balance: {}", amount, vault.balance);
        Ok(())
    }

    /// ⚠️ VULNERABLE: Withdraw without proper signer check!
    /// 
    /// BUG: The `authority` is AccountInfo, not Signer<'info>
    /// Anyone can pass any pubkey as authority without signing!
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        // This check is USELESS because we never verify authority signed!
        require_keys_eq!(vault.authority, ctx.accounts.authority.key(), VaultError::Unauthorized);
        require!(vault.balance >= amount, VaultError::InsufficientFunds);
        
        vault.balance = vault.balance.checked_sub(amount).unwrap();
        
        // Transfer lamports back to authority
        **vault.to_account_info().try_borrow_mut_lamports()? -= amount;
        **ctx.accounts.authority.try_borrow_mut_lamports()? += amount;
        
        msg!("Withdrew: {}. Remaining: {}", amount, vault.balance);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + Vault::INIT_SPACE,
        seeds = [b"vault", authority.key().as_ref()],
        bump
    )]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub depositor: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    
    // ⚠️ BUG: This should be Signer<'info> but is AccountInfo!
    // Anyone can pass any pubkey here without proving they own it!
    /// CHECK: VULNERABLE - Not checking if this account signed
    #[account(mut)]
    pub authority: AccountInfo<'info>,
}

#[account]
#[derive(InitSpace)]
pub struct Vault {
    pub authority: Pubkey,  // 32 bytes
    pub balance: u64,       // 8 bytes
}

#[error_code]
pub enum VaultError {
    #[msg("Unauthorized access")]
    Unauthorized,
    #[msg("Insufficient funds in vault")]
    InsufficientFunds,
}
