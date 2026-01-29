use anchor_lang::prelude::*;
use anchor_lang::solana_program::{program::invoke_signed, instruction::Instruction, instruction::AccountMeta};

declare_id!("9ZCkE1ngX2RrFHgMeZQ16kCEbPg3bgsKpvGY1T38ncW4");

/// # Arbitrary CPI Signer Vulnerability
/// 
/// This program creates a PDA that can sign CPIs, but allows users to specify
/// arbitrary instruction data and accounts, enabling privilege escalation.

#[program]
pub mod arbitrary_cpi_vulnerable {
    use super::*;

    /// Executes a user-supplied CPI, signed by the program's PDA.
    /// 
    /// ## Vulnerability: Arbitrary CPI Signing
    /// 
    /// The program accepts arbitrary `data` from the user and constructs an
    /// instruction that it signs with the PDA. An attacker can craft any
    /// instruction (e.g., `SystemProgram::Transfer`) to steal assets held
    /// by the PDA.
    /// 
    /// ## Exploit Scenario:
    /// 1. The PDA holds SOL (e.g., from fees or deposits).
    /// 2. Attacker crafts `SystemProgram::Transfer` instruction data.
    /// 3. Attacker calls `proxied_cpi` with:
    ///    - `target_program`: System Program
    ///    - `data`: Transfer instruction encoding
    ///    - `destination`: Attacker's wallet
    /// 4. Program signs the instruction with the PDA.
    /// 5. SOL is transferred from PDA to Attacker.
    pub fn proxied_cpi(ctx: Context<ProxiedCpi>, data: Vec<u8>) -> Result<()> {
        let ix = Instruction {
            program_id: *ctx.accounts.target_program.key,
            accounts: vec![
                AccountMeta::new(*ctx.accounts.pda_signer.key, true), // PDA signs
                AccountMeta::new(*ctx.accounts.destination.key, false), 
            ],
            data, // Vulnerability: User-controlled instruction data
        };

        invoke_signed(
            &ix,
            &[
                ctx.accounts.destination.to_account_info(),
                ctx.accounts.pda_signer.to_account_info(),
                ctx.accounts.target_program.to_account_info(),
            ],
            &[&[b"signer", &[ctx.bumps.pda_signer]]],
        )?;
        
        emit!(ArbitraryCpiExecuted {
            target: ctx.accounts.target_program.key(),
            destination: ctx.accounts.destination.key(),
        });

        Ok(())
    }
}

#[derive(Accounts)]
pub struct ProxiedCpi<'info> {
    #[account(
        mut,
        seeds = [b"signer"],
        bump,
    )]
    /// CHECK: This is the PDA that signs. Holds program assets.
    pub pda_signer: UncheckedAccount<'info>,
    
    /// CHECK: Vulnerability - Arbitrary destination for funds.
    #[account(mut)]
    pub destination: UncheckedAccount<'info>,
    
    /// CHECK: Vulnerability - Any program can be called.
    pub target_program: UncheckedAccount<'info>,
}

#[event]
pub struct ArbitraryCpiExecuted {
    pub target: Pubkey,
    pub destination: Pubkey,
}
