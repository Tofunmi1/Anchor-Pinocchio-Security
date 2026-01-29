use anchor_lang::prelude::*;
use anchor_lang::solana_program::{program::invoke, instruction::Instruction};

declare_id!("GJsiEMJS2dR8nrMxHPXiGmHTb2Sh5iQUiv8vdLf2ie39");

/// # Unchecked Program ID Vulnerability
/// 
/// This program performs a CPI (Cross-Program Invocation) but fails to verify
/// that the target program is the expected one. An attacker can substitute
/// a malicious program that returns success for any instruction.

#[program]
pub mod unchecked_program_id_vulnerable {
    use super::*;

    /// Executes a CPI to a target program.
    /// 
    /// ## Vulnerability: Unchecked Program ID
    /// 
    /// The `target_program` account is `UncheckedAccount`, meaning any program
    /// can be passed. If an attacker passes a malicious program that always
    /// succeeds, the calling program may incorrectly assume the CPI completed
    /// its intended action (e.g., token transfer, state update).
    /// 
    /// ## Exploit Scenario:
    /// 1. Program expects to call the Token Program for a deposit.
    /// 2. Attacker creates a malicious program that logs "success" and returns Ok.
    /// 3. Attacker passes malicious program as `target_program`.
    /// 4. Program updates internal state ("User deposited 1M USDC").
    /// 5. No actual token transfer occurred.
    pub fn cpi_log(ctx: Context<CpiLog>) -> Result<()> {
        let ix = Instruction {
            program_id: *ctx.accounts.target_program.key, // Vulnerability: Untrusted
            accounts: vec![],
            data: b"Hello".to_vec(),
        };
        
        msg!("Invoking CPI to {}", ctx.accounts.target_program.key);
        invoke(&ix, &[ctx.accounts.target_program.to_account_info()])?;
        
        emit!(CpiExecuted {
            target: ctx.accounts.target_program.key(),
        });
        
        Ok(())
    }
}

#[derive(Accounts)]
pub struct CpiLog<'info> {
    /// CHECK: Vulnerability - No program ID verification. Any executable can be passed.
    pub target_program: UncheckedAccount<'info>,
}

#[event]
pub struct CpiExecuted {
    pub target: Pubkey,
}
