//! Unchecked Program ID Vulnerability - FIXED
//!
//! SECURE: Verifies target program ID before CPI.

use pinocchio::{
    account_info::AccountInfo,
    entrypoint,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
    ProgramResult,
};

entrypoint!(process_instruction);

const INVOKE_CPI: u8 = 0;

// Token Program ID (example)
const TOKEN_PROGRAM_ID: Pubkey = pinocchio::pubkey!("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");

pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    if instruction_data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }

    match instruction_data[0] {
        INVOKE_CPI => process_cpi(accounts),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

/// FIXED: Verifies target program ID before CPI
///
/// Security Model:
/// 1. Compare target_program.key() against expected program ID
/// 2. Only proceed if it matches the trusted program
fn process_cpi(accounts: &[AccountInfo]) -> ProgramResult {
    let [target_program, caller] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !caller.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // === THE FIX ===
    // Verify target program is the expected Token Program
    if target_program.key() != &TOKEN_PROGRAM_ID {
        msg!("Invalid program ID: expected Token Program");
        return Err(ProgramError::IncorrectProgramId);
    }

    // Also verify the account is executable
    if !target_program.is_executable() {
        msg!("Target is not an executable program");
        return Err(ProgramError::InvalidAccountData);
    }

    msg!("Invoking verified CPI to Token Program");

    // Now safe to perform CPI - we know it's the real Token Program

    msg!("CPI completed - state updated safely");
    Ok(())
}
