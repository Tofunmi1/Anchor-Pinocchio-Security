use anchor_lang::prelude::*;
use anchor_lang::solana_program::{program::invoke, instruction::Instruction};

declare_id!("Grv8BFhBmJTMXHWM5Hg1uR6gsZ39wqvkf6RVuqTavRaN");

/// # Secure: Checked Program ID
/// 
/// This program enforces that the CPI target is a specific, trusted program.
/// Anchor's `Program<'info, T>` type automatically verifies the program ID.

#[program]
pub mod unchecked_program_id_fixed {
    use super::*;

    /// Executes a CPI to the System Program.
    /// 
    /// ## Secure Pattern: Typed Program Account
    /// 
    /// By using `Program<'info, System>`, Anchor automatically validates that
    /// the provided account has the correct program ID (System Program). 
    /// Any attempt to substitute a malicious program will fail with
    /// `ConstraintAddress` error before the instruction logic executes.
    pub fn cpi_log(ctx: Context<CpiLog>) -> Result<()> {
        let ix = Instruction {
            program_id: *ctx.accounts.target_program.key,
            accounts: vec![],
            data: b"Hello".to_vec(),
        };
        
        msg!("Invoking CPI to verified System Program");
        invoke(&ix, &[ctx.accounts.target_program.to_account_info()])?;

        emit!(CpiExecuted {
            target: ctx.accounts.target_program.key(),
        });
        
        Ok(())
    }
}

#[derive(Accounts)]
pub struct CpiLog<'info> {
    /// Secure: Anchor enforces that this must be the System Program.
    pub target_program: Program<'info, System>,
}

#[event]
pub struct CpiExecuted {
    pub target: Pubkey,
}
