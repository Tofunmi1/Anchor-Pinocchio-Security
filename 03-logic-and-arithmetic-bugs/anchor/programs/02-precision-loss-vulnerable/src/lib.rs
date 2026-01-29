use anchor_lang::prelude::*;

declare_id!("6FeGwNoqLxYZWatLH9v1Jcrjo1si3H1NrTSupxfYDugn");

/// VULNERABLE: Precision Loss
/// 
/// This program performs integer division before multiplication,
/// resulting in severe precision loss and rounding errors.
/// Usually funds are lost (locked in contract) or calculation result is 0.

#[program]
pub mod precision_loss_vulnerable {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        pool.total_assets = 10_000_000; // 10k USDC (6 decimals) assuming example
        pool.total_shares = 1_000;      // 1000 shares
        Ok(())
    }

    /// Calculate user share value
    /// 
    /// BUG: Division before multiplication
    /// If user_shares < total_shares, the result is 0
    pub fn withdraw_share(ctx: Context<WithdrawShare>, shares: u64) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        let user = &mut ctx.accounts.user;
        
        // BUG: Integer division rounds down to nearest integer
        // If shares (e.g. 10) < total_shares (1000), result is 0
        // 10 / 1000 = 0
        // 0 * total_assets = 0
        let amount = (shares / pool.total_shares) * pool.total_assets;

        user.last_withdrawal = amount;
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
