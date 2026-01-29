use anchor_lang::prelude::*;

declare_id!("AWZ7VNRtQjFkfZnrLwG46znQ14yC8EefoydvzPu3Tkoq");

/// VULNERABLE: Reinitialization Attack
/// 
/// This program uses init_if_needed without checking if account
/// is already initialized. Anyone can reinitialize and take ownership.

#[program]
pub mod reinitialization_vulnerable {
    use super::*;

    /// Initialize or update config - VULNERABLE!
    /// 
    /// BUG: Uses init_if_needed but always overwrites owner
    /// This allows any attacker to reinitialize and become owner
    pub fn initialize_or_update(ctx: Context<InitializeOrUpdate>, value: u64) -> Result<()> {
        let config = &mut ctx.accounts.config;
        
        // BUG: Always overwrites owner, even if account exists!
        config.owner = ctx.accounts.payer.key();
        config.value = value;
        
        msg!("Config set: owner={}, value={}", config.owner, config.value);
        Ok(())
    }

    /// Update value - only owner should be able to do this
    pub fn update_value(ctx: Context<UpdateValue>, new_value: u64) -> Result<()> {
        let config = &mut ctx.accounts.config;
        require_keys_eq!(config.owner, ctx.accounts.owner.key(), ConfigError::NotOwner);
        
        config.value = new_value;
        msg!("Value updated to: {}", new_value);
        Ok(())
    }

    /// Withdraw - only owner can withdraw
    pub fn withdraw(ctx: Context<Withdraw>) -> Result<()> {
        let config = &ctx.accounts.config;
        require_keys_eq!(config.owner, ctx.accounts.owner.key(), ConfigError::NotOwner);
        
        // Transfer all lamports to owner
        let config_info = ctx.accounts.config.to_account_info();
        let owner_info = ctx.accounts.owner.to_account_info();
        
        let rent = Rent::get()?;
        let min_rent = rent.minimum_balance(Config::INIT_SPACE + 8);
        let withdrawable = config_info.lamports().saturating_sub(min_rent);
        
        **config_info.try_borrow_mut_lamports()? -= withdrawable;
        **owner_info.try_borrow_mut_lamports()? += withdrawable;
        
        msg!("Withdrew {} lamports", withdrawable);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct InitializeOrUpdate<'info> {
    #[account(
        init_if_needed,  // <-- VULNERABLE: allows reinitialization
        payer = payer,
        space = 8 + Config::INIT_SPACE,
        seeds = [b"config"],
        bump
    )]
    pub config: Account<'info, Config>,
    
    #[account(mut)]
    pub payer: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UpdateValue<'info> {
    #[account(mut)]
    pub config: Account<'info, Config>,
    pub owner: Signer<'info>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub config: Account<'info, Config>,
    #[account(mut)]
    pub owner: Signer<'info>,
}

#[account]
#[derive(InitSpace)]
pub struct Config {
    pub owner: Pubkey,  // 32 bytes
    pub value: u64,     // 8 bytes
}

#[error_code]
pub enum ConfigError {
    #[msg("Only the owner can perform this action")]
    NotOwner,
}
