use anchor_lang::prelude::*;

declare_id!("Acc3HTF6PvkATUhAP3Nvh6T5szSmKJ3G5ivhPpBbTozZ");

/// FIXED: Safe Integer Arithmetic
/// 
/// This program uses checked arithmetic which returns errors on overflow/underflow,
/// preventing unexpected behavior and fund loss.

#[program]
pub mod integer_overflow_fixed {
    use super::*;

    /// Initialize a staking pool
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        pool.authority = ctx.accounts.authority.key();
        pool.total_staked = 0;
        pool.reward_rate = 100;
        pool.last_update = Clock::get()?.unix_timestamp as u64;
        Ok(())
    }

    /// Stake tokens - FIX: uses checked_add
    /// 
    /// checked_add returns None on overflow, which we convert to an error
    pub fn stake(ctx: Context<Stake>, amount: u64) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        let user = &mut ctx.accounts.user_stake;

        // FIX: checked_add returns None on overflow
        pool.total_staked = pool.total_staked
            .checked_add(amount)
            .ok_or(ArithmeticError::Overflow)?;

        user.staked_amount = user.staked_amount
            .checked_add(amount)
            .ok_or(ArithmeticError::Overflow)?;

        msg!("Staked: {}. Total: {}", amount, pool.total_staked);
        Ok(())
    }

    /// Withdraw tokens - FIX: uses checked_sub with balance check
    /// 
    /// checked_sub returns None on underflow
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        let user = &mut ctx.accounts.user_stake;

        // FIX: Explicit balance check + checked_sub
        require!(user.staked_amount >= amount, ArithmeticError::InsufficientBalance);

        user.staked_amount = user.staked_amount
            .checked_sub(amount)
            .ok_or(ArithmeticError::Underflow)?;

        pool.total_staked = pool.total_staked
            .checked_sub(amount)
            .ok_or(ArithmeticError::Underflow)?;

        msg!("Withdrew: {}. Remaining: {}", amount, user.staked_amount);
        Ok(())
    }

    /// Calculate rewards - FIX: uses u128 for intermediate calculation
    /// 
    /// Cast to u128 for multiplication, then cap result at u64::MAX
    pub fn calculate_rewards(ctx: Context<CalculateRewards>) -> Result<u64> {
        let pool = &ctx.accounts.pool;
        let user = &ctx.accounts.user_stake;

        let current_time = Clock::get()?.unix_timestamp as u64;
        let time_elapsed = current_time
            .checked_sub(pool.last_update)
            .ok_or(ArithmeticError::Underflow)?;

        // FIX: Use u128 for intermediate calculation to prevent overflow
        let reward_u128 = (user.staked_amount as u128)
            .checked_mul(pool.reward_rate as u128)
            .ok_or(ArithmeticError::Overflow)?
            .checked_mul(time_elapsed as u128)
            .ok_or(ArithmeticError::Overflow)?;

        // Cap at u64::MAX or convert safely
        let reward = if reward_u128 > u64::MAX as u128 {
            u64::MAX
        } else {
            reward_u128 as u64
        };

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
    pub authority: Pubkey,
    pub total_staked: u64,
    pub reward_rate: u64,
    pub last_update: u64,
}

#[account]
#[derive(InitSpace)]
pub struct UserStake {
    pub staked_amount: u64,
    pub last_claim: u64,
}

#[error_code]
pub enum ArithmeticError {
    #[msg("Arithmetic overflow")]
    Overflow,
    #[msg("Arithmetic underflow")]
    Underflow,
    #[msg("Insufficient balance")]
    InsufficientBalance,
}
