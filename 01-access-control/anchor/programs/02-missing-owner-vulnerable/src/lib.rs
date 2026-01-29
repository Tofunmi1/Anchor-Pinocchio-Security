use anchor_lang::prelude::*;

declare_id!("FS2bmiDeTvd7f4AkdqGgkJiYRztyCcHKVxAH7YTVCw9M");

/// VULNERABLE: Missing Owner Check
/// 
/// This program accepts any account without verifying it's owned by this program.
/// An attacker can create a fake account with crafted data and pass it in.
///
/// Real-world Impact: Cashio ($52M exploit, 2022)

#[program]
pub mod missing_owner_vulnerable {
    use super::*;

    /// Initialize a vault - this is fine
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.owner = ctx.accounts.owner.key();
        vault.balance = 0;
        vault.is_locked = false;
        msg!("Vault initialized");
        Ok(())
    }

    /// Deposit into vault - this is fine
    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        **ctx.accounts.depositor.to_account_info().try_borrow_mut_lamports()? -= amount;
        **vault.to_account_info().try_borrow_mut_lamports()? += amount;
        
        vault.balance = vault.balance.checked_add(amount).unwrap();
        msg!("Deposited: {}", amount);
        Ok(())
    }

    /// VULNERABLE: Withdraw without owner verification
    /// 
    /// BUG: The vault account is UncheckedAccount - we manually deserialize
    /// but never verify that vault.owner == program_id
    /// 
    /// Attack: Create a fake account with System Program as owner,
    /// craft data where "owner" field = attacker's pubkey,
    /// pass it to this function and drain funds.
    pub fn withdraw_vulnerable(ctx: Context<WithdrawVulnerable>, amount: u64) -> Result<()> {
        let vault_info = &ctx.accounts.vault;
        let vault_data = vault_info.try_borrow_data()?;
        
        // BUG: No check that vault_info.owner() == program_id!
        // Anyone can pass any account here
        
        // Manually parse data (skipping 8-byte discriminator)
        let owner = Pubkey::try_from(&vault_data[8..40]).unwrap();
        let balance = u64::from_le_bytes(vault_data[40..48].try_into().unwrap());
        
        // This check is useless - attacker controls the data!
        require_keys_eq!(owner, ctx.accounts.owner.key(), VaultError::Unauthorized);
        require!(balance >= amount, VaultError::InsufficientFunds);
        
        drop(vault_data);
        
        // Transfer lamports
        **vault_info.try_borrow_mut_lamports()? -= amount;
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
pub struct WithdrawVulnerable<'info> {
    // BUG: UncheckedAccount doesn't verify owner
    /// CHECK: VULNERABLE - No owner verification
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,
    
    #[account(mut)]
    pub owner: Signer<'info>,
}

#[account]
#[derive(InitSpace)]
pub struct Vault {
    pub owner: Pubkey,     // 32 bytes
    pub balance: u64,      // 8 bytes
    pub is_locked: bool,   // 1 byte
}

#[error_code]
pub enum VaultError {
    #[msg("Unauthorized")]
    Unauthorized,
    #[msg("Insufficient funds")]
    InsufficientFunds,
}
