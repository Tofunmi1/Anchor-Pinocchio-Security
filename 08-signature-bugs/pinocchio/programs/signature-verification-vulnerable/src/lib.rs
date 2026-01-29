//! Signature Verification Vulnerability - Pinocchio Implementation
//!
//! VULNERABLE: Does not verify Ed25519 signatures properly.

use pinocchio::{
    account_info::AccountInfo,
    entrypoint,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
    ProgramResult,
};

entrypoint!(process_instruction);

const VERIFY_AND_EXECUTE: u8 = 0;

pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    if instruction_data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }

    match instruction_data[0] {
        VERIFY_AND_EXECUTE => process_verify_and_execute(accounts, &instruction_data[1..]),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

/// VULNERABLE: Does not verify signature at all!
///
/// BUG: Accepts message and signature but never actually verifies.
/// Attacker can pass any message with a fake signature.
fn process_verify_and_execute(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let [_signer, _ed25519_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // Parse message and signature from data
    if data.len() < 96 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let _signature = &data[0..64];
    let _message = &data[64..];

    // BUG: Never actually calls ed25519_verify!
    // We should verify the signature against the message and pubkey
    
    // Incorrectly assume signature is valid
    msg!("Processing message (VULNERABLE - signature not verified!)");
    
    // Execute privileged operation without verification
    msg!("Executing privileged operation...");
    
    Ok(())
}
