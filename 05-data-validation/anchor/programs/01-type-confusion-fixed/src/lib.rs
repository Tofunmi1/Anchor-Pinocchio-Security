use anchor_lang::prelude::*;

declare_id!("ETrcTSafZgKTtt3ZciF2rinSrzAXLsLHeRveER1JkdvQ");

/// # Secure: Type-Safe Account Handling
///
/// This program uses Anchor's `Account<'info, T>` wrapper which automatically
/// verifies the account's discriminator matches the expected type `T`.

#[program]
pub mod type_confusion_fixed {
    use super::*;

    /// Creates a new User account with a specified ID.
    pub fn initialize_user(ctx: Context<InitializeUser>, id: u64) -> Result<()> {
        let user = &mut ctx.accounts.user;
        user.id = id;
        
        emit!(UserInitialized {
            user: user.key(),
            id,
        });
        
        Ok(())
    }

    /// Creates a new AdminConfig account with a specified admin ID.
    pub fn initialize_admin(ctx: Context<InitializeAdmin>, admin_id: u64) -> Result<()> {
        let config = &mut ctx.accounts.admin_config;
        config.admin_id = admin_id;
        
        emit!(AdminConfigInitialized {
            config: config.key(),
            admin_id,
        });
        
        Ok(())
    }

    /// Allows an admin to withdraw tokens (simulated).
    /// 
    /// ## Secure Pattern: Typed Account Validation
    /// 
    /// By using `Account<'info, AdminConfig>`, Anchor automatically:
    /// 1. Reads the first 8 bytes of the account data (discriminator).
    /// 2. Compares it against `AdminConfig`'s expected discriminator.
    /// 3. Rejects the transaction if they don't match.
    /// 
    /// If an attacker tries to pass a `User` account, the discriminator check
    /// fails BEFORE the instruction logic executes.
    pub fn admin_withdraw(ctx: Context<AdminWithdraw>, amount: u64) -> Result<()> {
        // Secure: Anchor already verified this is an AdminConfig account
        let config = &ctx.accounts.admin_config;
        
        require!(
            config.admin_id == ctx.accounts.authority.key().to_bytes()[0] as u64, 
            AdminError::NotAdmin
        );
        
        emit!(AdminWithdrawn {
            admin: ctx.accounts.authority.key(),
            amount,
        });
        
        msg!("Admin withdrawn {} tokens (simulated)", amount);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct InitializeUser<'info> {
    #[account(init, payer = signer, space = 8 + User::INIT_SPACE)]
    pub user: Account<'info, User>,
    #[account(mut)]
    pub signer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct InitializeAdmin<'info> {
    #[account(init, payer = signer, space = 8 + AdminConfig::INIT_SPACE)]
    pub admin_config: Account<'info, AdminConfig>,
    #[account(mut)]
    pub signer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct AdminWithdraw<'info> {
    /// Secure: Anchor validates discriminator automatically.
    pub admin_config: Account<'info, AdminConfig>,
    pub authority: Signer<'info>,
}

#[account]
#[derive(InitSpace)]
pub struct User {
    pub id: u64,
}

#[account]
#[derive(InitSpace)]
pub struct AdminConfig {
    pub admin_id: u64,
}

#[event]
pub struct UserInitialized {
    pub user: Pubkey,
    pub id: u64,
}

#[event]
pub struct AdminConfigInitialized {
    pub config: Pubkey,
    pub admin_id: u64,
}

#[event]
pub struct AdminWithdrawn {
    pub admin: Pubkey,
    pub amount: u64,
}

#[error_code]
pub enum AdminError {
    #[msg("Caller is not an authorized admin.")]
    NotAdmin,
}
