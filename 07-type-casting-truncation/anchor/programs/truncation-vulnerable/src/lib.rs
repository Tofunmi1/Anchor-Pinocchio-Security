use anchor_lang::prelude::*;

declare_id!("GExP8D2AMvf8g1J178NFEAwYz1MLLC5u8LPsHe2dWjCv");

/// Simple demonstration of type casting truncation vulnerability

#[program]
pub mod truncation_vulnerable {
    use super::*;

    /// Initialize counter with a value
    pub fn initialize(ctx: Context<Initialize>, value: u64) -> Result<()> {
        ctx.accounts.state.value = value;
        ctx.accounts.state.authority = ctx.accounts.authority.key();
        Ok(())
    }

    /// Calculate and store a result using unsafe `as` cast
    /// 
    /// VULNERABILITY: Using `as u64` silently truncates values > u64::MAX
    pub fn calculate(ctx: Context<Calculate>, multiplier: u64) -> Result<()> {
        let state = &mut ctx.accounts.state;
        
        // Do calculation in u128 to avoid overflow
        let result_u128: u128 = (state.value as u128) * (multiplier as u128);
        
        msg!("Value: {}, Multiplier: {}", state.value, multiplier);
        msg!("Result (u128): {}", result_u128);
        
        // ❌ VULNERABLE: Silent truncation!
        let result: u64 = result_u128 as u64;
        
        msg!("Result (u64 truncated): {}", result);
        
        state.result = result;
        
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = authority, space = 8 + State::INIT_SPACE)]
    pub state: Account<'info, State>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Calculate<'info> {
    #[account(mut, has_one = authority)]
    pub state: Account<'info, State>,
    pub authority: Signer<'info>,
}

#[account]
#[derive(InitSpace)]
pub struct State {
    pub value: u64,
    pub result: u64,
    pub authority: Pubkey,
}
