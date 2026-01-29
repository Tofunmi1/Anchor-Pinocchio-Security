use anchor_lang::prelude::*;

declare_id!("99TU6jpz8cu7gCVJKriHL3wHaDdTZUwzayEW59SreAB");

/// VULNERABLE: Integer Overflow/Underflow
/// 
/// This program uses unchecked arithmetic which can overflow or underflow,
/// leading to unexpected behavior and potential fund loss.

#[program]
pub mod integer_overflow_vulnerable {
    use super::*;

    /// Initialize a staking pool
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        pool.authority = ctx.accounts.authority.key();
        pool.total_staked = 0;
        pool.reward_rate = 100; // 100 tokens per second base rate
        pool.last_update = Clock::get()?.unix_timestamp as u64;
        Ok(())
    }

    /// Stake tokens - VULNERABLE to overflow
    /// 
    /// BUG: Uses wrapping arithmetic - large stake can overflow total_staked
    pub fn stake(ctx: Context<Stake>, amount: u64) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        let user = &mut ctx.accounts.user_stake;

        // BUG: Wrapping add can overflow!
        // If total_staked = u64::MAX - 100 and amount = 200
        // Result wraps to 99 instead of failing
        pool.total_staked = pool.total_staked.wrapping_add(amount);
        user.staked_amount = user.staked_amount.wrapping_add(amount);

        msg!("Staked: {}. Total: {}", amount, pool.total_staked);
        Ok(())
    }

    /// Withdraw tokens - VULNERABLE to underflow
    /// 
    /// BUG: Uses wrapping arithmetic - can underflow to large number
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        let user = &mut ctx.accounts.user_stake;

        // BUG: Wrapping sub can underflow!
        // If user.staked_amount = 50 and amount = 100
        // Result wraps to u64::MAX - 49 instead of failing
        user.staked_amount = user.staked_amount.wrapping_sub(amount);
        pool.total_staked = pool.total_staked.wrapping_sub(amount);

        msg!("Withdrew: {}. Remaining: {}", amount, user.staked_amount);
        Ok(())
    }

    /// Calculate rewards - VULNERABLE to overflow in multiplication
    /// 
    /// BUG: Large values can overflow during reward calculation
    pub fn calculate_rewards(ctx: Context<CalculateRewards>) -> Result<u64> {
        let pool = &ctx.accounts.pool;
        let user = &ctx.accounts.user_stake;

        let current_time = Clock::get()?.unix_timestamp as u64;
        let time_elapsed = current_time.wrapping_sub(pool.last_update);

        // BUG: Multiplication overflow!
        // staked_amount * reward_rate * time_elapsed can easily overflow
        // Example: 10^18 * 100 * 86400 = overflow
        let reward = user.staked_amount
            .wrapping_mul(pool.reward_rate)
            .wrapping_mul(time_elapsed);

        msg!("Calculated reward: {}", reward);
        Ok(reward)
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + StakingPool::INIT_SPACE,
        seeds = [b"pool"],
        bump
    )]
    pub pool: Account<'info, StakingPool>,
    
    #[account(mut)]
    pub authority: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Stake<'info> {
    #[account(mut)]
    pub pool: Account<'info, StakingPool>,
    
    #[account(
        init_if_needed,
        payer = staker,
        space = 8 + UserStake::INIT_SPACE,
        seeds = [b"user_stake", staker.key().as_ref()],
        bump
    )]
    pub user_stake: Account<'info, UserStake>,
    
    #[account(mut)]
    pub staker: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub pool: Account<'info, StakingPool>,
    
    #[account(mut)]
    pub user_stake: Account<'info, UserStake>,
    
    pub staker: Signer<'info>,
}

#[derive(Accounts)]
pub struct CalculateRewards<'info> {
    pub pool: Account<'info, StakingPool>,
    pub user_stake: Account<'info, UserStake>,
}

#[account]
#[derive(InitSpace)]
pub struct StakingPool {
    pub authority: Pubkey,    // 32
    pub total_staked: u64,    // 8
    pub reward_rate: u64,     // 8
    pub last_update: u64,     // 8
}

#[account]
#[derive(InitSpace)]
pub struct UserStake {
    pub staked_amount: u64,   // 8
    pub last_claim: u64,      // 8
}
