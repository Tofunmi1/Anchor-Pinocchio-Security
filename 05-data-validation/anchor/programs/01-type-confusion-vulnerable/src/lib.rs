use anchor_lang::prelude::*;

declare_id!("E7efDRg2YiEW4TGMwUvBkv8EE8JUqC86DfxLBHdQ5zZh");

/// # Type Confusion Vulnerability
///
/// This program manually deserializes an account without checking its discriminator.
/// An attacker can pass a `User` account in place of an `AdminConfig` account,
/// tricking the program into granting admin privileges.

#[program]
pub mod type_confusion_vulnerable {
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
    /// ## Vulnerability: Type Confusion via Manual Deserialization
    /// 
    /// The program accepts `admin_config` as `UncheckedAccount` and manually
    /// deserializes it by skipping the 8-byte discriminator. This allows an
    /// attacker to pass any account with matching field layout.
    /// 
    /// ## Exploit Scenario:
    /// 1. Both `User` and `AdminConfig` structs have a `u64` field at offset 8.
    /// 2. Attacker creates a `User` account with `id = authorized_admin_id`.
    /// 3. Attacker passes this User account as `admin_config`.
    /// 4. Program skips discriminator and reads `User.id` as `AdminConfig.admin_id`.
    /// 5. The check `admin_id == authority_id` passes, granting admin access.
    /// 
    /// ## Memory Layout Comparison:
    /// ```
    /// User Account:        [User Discriminator (8)] [id: u64 (8)]
    /// AdminConfig Account: [Admin Discriminator (8)] [admin_id: u64 (8)]
    ///                                                 ^
    ///                                                 | Program reads here after skipping 8 bytes
    /// ```
    pub fn admin_withdraw(ctx: Context<AdminWithdraw>, amount: u64) -> Result<()> {
        let account_data = ctx.accounts.admin_config.try_borrow_data()?;
        if account_data.len() < 8 + 8 {
            return Err(ProgramError::InvalidAccountData.into());
        }
        
        // Vulnerability: Skip discriminator without verifying it
        let mut data_slice = &account_data[8..];
        let config = AdminConfig::deserialize(&mut data_slice)?;

        // Simplified check: admin_id matches first byte of authority pubkey
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
    /// CHECK: Vulnerability - Unchecked account allows type confusion attack.
    pub admin_config: UncheckedAccount<'info>,
    pub authority: Signer<'info>,
}

#[account]
#[derive(InitSpace)]
pub struct User {
    pub id: u64, // Offset 8: Same position as AdminConfig.admin_id
}

#[account]
#[derive(InitSpace)]
pub struct AdminConfig {
    pub admin_id: u64, // Offset 8: Same position as User.id
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
