use anchor_lang::prelude::*;

declare_id!("9grzLTNdQjm3onsaU47WcN8JD8DorU2gyfWp6emRDtP8");

/// Fixed version using try_from to prevent truncation

#[program]
pub mod truncation_fixed {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>, value: u64) -> Result<()> {
        ctx.accounts.state.value = value;
        ctx.accounts.state.authority = ctx.accounts.authority.key();
        Ok(())
    }

    /// Calculate and store a result using safe try_from
    /// 
    /// FIX: Using try_from returns error if value doesn't fit
    pub fn calculate(ctx: Context<Calculate>, multiplier: u64) -> Result<()> {
        let state = &mut ctx.accounts.state;
        
        let result_u128: u128 = (state.value as u128) * (multiplier as u128);
        
        msg!("Value: {}, Multiplier: {}", state.value, multiplier);
        msg!("Result (u128): {}", result_u128);
        
        // ✅ FIXED: try_from returns error if truncation would occur
        let result: u64 = u64::try_from(result_u128)
            .map_err(|_| error!(ErrorCode::Overflow))?;
        
        msg!("Result (u64 safe): {}", result);
        
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

#[error_code]
pub enum ErrorCode {
    #[msg("Result too large for u64")]
    Overflow,
}
