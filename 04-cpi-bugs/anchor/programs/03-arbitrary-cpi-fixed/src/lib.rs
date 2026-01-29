use anchor_lang::prelude::*;
use anchor_lang::solana_program::{program::invoke_signed, system_instruction};

declare_id!("4NyX5VfGwY2MhhWpPwd816AnEaW9kBgdB91Kwct4QTcg");

/// # Secure: Controlled CPI Signing
/// 
/// This program demonstrates the secure pattern for PDA-signed CPIs.
/// The instruction data is constructed entirely within the program logic,
/// preventing users from specifying arbitrary operations.

#[program]
pub mod arbitrary_cpi_fixed {
    use super::*;

    /// Rewards a user with a fixed amount from the PDA treasury.
    /// 
    /// ## Secure Pattern: Program-Controlled CPI
    /// 
    /// Instead of accepting arbitrary instruction data from the user, the
    /// program hardcodes the CPI logic (transfer a fixed reward amount).
    /// The user can only specify the destination, but the amount and
    /// operation type are controlled by the program.
    /// 
    /// Additional security measures:
    /// - Amount is defined as a constant (not user-supplied).
    /// - Target program is enforced as System Program via Anchor type.
    pub fn claim_reward(ctx: Context<ClaimReward>) -> Result<()> {
        const REWARD_AMOUNT: u64 = 10_000; // Fixed reward amount (lamports)
        
        // Secure: The instruction is constructed by the program, not the user
        let ix = system_instruction::transfer(
            ctx.accounts.pda_treasury.key,
            ctx.accounts.recipient.key,
            REWARD_AMOUNT,
        );

        invoke_signed(
            &ix,
            &[
                ctx.accounts.pda_treasury.to_account_info(),
                ctx.accounts.recipient.to_account_info(),
                ctx.accounts.system_program.to_account_info(),
            ],
            &[&[b"treasury", &[ctx.bumps.pda_treasury]]],
        )?;
        
        emit!(RewardClaimed {
            recipient: ctx.accounts.recipient.key(),
            amount: REWARD_AMOUNT,
        });

        Ok(())
    }
}

#[derive(Accounts)]
pub struct ClaimReward<'info> {
    #[account(
        mut,
        seeds = [b"treasury"],
        bump,
    )]
    /// CHECK: PDA treasury that holds rewards. Program-owned.
    pub pda_treasury: UncheckedAccount<'info>,
    
    /// Secure: Recipient must sign to claim their reward.
    #[account(mut)]
    pub recipient: Signer<'info>,
    
    /// Secure: Enforced as System Program via type constraint.
    pub system_program: Program<'info, System>,
}

#[event]
pub struct RewardClaimed {
    pub recipient: Pubkey,
    pub amount: u64,
}
