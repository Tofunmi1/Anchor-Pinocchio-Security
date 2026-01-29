use anchor_lang::prelude::*;

declare_id!("tBN98fzfGy2oZCpmCBAP5tvCsDausty8geDpZxQ8Bmj");

/// FIXED: Precision Loss Prevention
/// 
/// This program performs multiplication before division
/// and uses u128 to prevent overflow during intermediate steps.

#[program]
pub mod precision_loss_fixed {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        pool.total_assets = 10_000_000;
        pool.total_shares = 1_000;
        Ok(())
    }

    /// Calculate user share value - FIXED
    /// 
    /// FIX: Multiplication before division ensures precision is maintained
    pub fn withdraw_share(ctx: Context<WithdrawShare>, shares: u64) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        let user = &mut ctx.accounts.user;

        // FIX: Cast to u128, multiply first, then divide
        // (10 * 10_000_000) / 1000 = 100_000_000 / 1000 = 100_000
        let amount_u128 = (shares as u128)
            .checked_mul(pool.total_assets as u128)
            .unwrap();
            
        let amount = amount_u128
            .checked_div(pool.total_shares as u128)
            .unwrap();

        user.last_withdrawal = amount as u64;
        msg!("Withdrawing {} shares. Amount calculated: {}", shares, amount);
        
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + Pool::INIT_SPACE,
        seeds = [b"pool"],
        bump
    )]
    pub pool: Account<'info, Pool>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct WithdrawShare<'info> {
    #[account(mut)]
    pub pool: Account<'info, Pool>,
    #[account(
        init_if_needed,
        payer = user_authority,
        space = 8 + User::INIT_SPACE,
        seeds = [b"user", user_authority.key().as_ref()],
        bump
    )]
    pub user: Account<'info, User>,
    #[account(mut)]
    pub user_authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[account]
#[derive(InitSpace)]
pub struct Pool {
    pub total_assets: u64,
    pub total_shares: u64,
}

#[account]
#[derive(InitSpace)]
pub struct User {
    pub last_withdrawal: u64,
}
