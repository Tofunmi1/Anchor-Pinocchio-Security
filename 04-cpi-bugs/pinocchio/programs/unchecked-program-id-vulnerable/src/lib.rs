//! Unchecked Program ID Vulnerability - Pinocchio Implementation
//!
//! VULNERABLE: Performs CPI without verifying target program ID.

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

// Expected program ID (e.g., Token Program)
const EXPECTED_PROGRAM_ID: [u8; 32] = [0; 32]; // Placeholder

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

/// VULNERABLE: Does not verify target program ID
///
/// BUG: Any program can be passed as target_program.
/// Attacker can substitute a malicious program that returns Ok(())
/// without performing the intended action.
fn process_cpi(accounts: &[AccountInfo]) -> ProgramResult {
    let [target_program, caller] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !caller.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // BUG: No check that target_program is the expected program!
    // Attacker can pass any executable program
    msg!("Invoking CPI to: {:?}", target_program.key());

    // Simulate CPI - in real code this would be invoke()
    // The vulnerability is that we trust any program passed by the caller

    // Update internal state assuming CPI succeeded
    msg!("CPI completed - updating internal state");
    msg!("User deposited funds (VULNERABLE - no verification!)");

    Ok(())
}
