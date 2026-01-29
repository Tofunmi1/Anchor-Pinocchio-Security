use anchor_lang::prelude::*;

declare_id!("AFFAJU5tJe7tQnrDjjBLjdLfqtmgruC1PJzwCyUe35E5");

/// FIXED: Reinitialization Prevention
/// 
/// This program uses `init` constraint which fails if account exists,
/// OR checks is_initialized flag when using init_if_needed.

#[program]
pub mod reinitialization_fixed {
    use super::*;

    /// Initialize config - uses `init` which fails if exists
    /// 
    /// FIX: `init` constraint errors if account already exists
    pub fn initialize(ctx: Context<Initialize>, value: u64) -> Result<()> {
        let config = &mut ctx.accounts.config;
        config.owner = ctx.accounts.payer.key();
        config.value = value;
        config.is_initialized = true;
        
        msg!("Config initialized: owner={}, value={}", config.owner, config.value);
        Ok(())
    }

    /// Alternative: init_if_needed with is_initialized check
    /// 
    /// FIX: Check is_initialized flag, reject if already set
    pub fn initialize_safe(ctx: Context<InitializeSafe>, value: u64) -> Result<()> {
        let config = &mut ctx.accounts.config;
        
        // FIX: Only set owner on first initialization
        if config.is_initialized {
            // Account exists - verify caller is owner
            require_keys_eq!(
                config.owner, 
                ctx.accounts.payer.key(), 
                ConfigError::AlreadyInitialized
            );
            // Only update value, not owner
            config.value = value;
        } else {
            // First initialization
            config.owner = ctx.accounts.payer.key();
            config.value = value;
            config.is_initialized = true;
        }
        
        msg!("Config set: owner={}, value={}", config.owner, config.value);
        Ok(())
    }

    /// Update value - only owner can call
    pub fn update_value(ctx: Context<UpdateValue>, new_value: u64) -> Result<()> {
        let config = &mut ctx.accounts.config;
        require_keys_eq!(config.owner, ctx.accounts.owner.key(), ConfigError::NotOwner);
        
        config.value = new_value;
        msg!("Value updated to: {}", new_value);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,  // <-- FIX: `init` fails if account exists
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
pub struct InitializeSafe<'info> {
    #[account(
        init_if_needed,
        payer = payer,
        space = 8 + Config::INIT_SPACE,
        seeds = [b"config_safe"],
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

#[account]
#[derive(InitSpace)]
pub struct Config {
    pub owner: Pubkey,       // 32 bytes
    pub value: u64,          // 8 bytes
    pub is_initialized: bool, // 1 byte - FIX: track initialization state
}

#[error_code]
pub enum ConfigError {
    #[msg("Only the owner can perform this action")]
    NotOwner,
    #[msg("Account is already initialized")]
    AlreadyInitialized,
}
