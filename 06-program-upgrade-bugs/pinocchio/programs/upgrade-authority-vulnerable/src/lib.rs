//! Upgrade Authority Vulnerability - Pinocchio Implementation
//!
//! VULNERABLE: Does not verify upgrade authority properly.

use pinocchio::{
    account_info::AccountInfo,
    entrypoint,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
    ProgramResult,
};

entrypoint!(process_instruction);

const SET_UPGRADE_AUTHORITY: u8 = 0;

// Program data layout
const UPGRADE_AUTHORITY_OFFSET: usize = 0;  // 32 bytes

pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    if instruction_data.len() < 33 {
        return Err(ProgramError::InvalidInstructionData);
    }

    match instruction_data[0] {
        SET_UPGRADE_AUTHORITY => {
            let mut new_authority = [0u8; 32];
            new_authority.copy_from_slice(&instruction_data[1..33]);
            process_set_authority(accounts, &new_authority)
        }
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

/// VULNERABLE: Weak authority verification
///
/// BUG: Only checks if caller is a signer, not if they are
/// the CURRENT upgrade authority
fn process_set_authority(accounts: &[AccountInfo], new_authority: &[u8; 32]) -> ProgramResult {
    let [program_data, caller] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // BUG: Only checks signer, not that caller IS the current authority
    if !caller.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let program_data_data = unsafe { program_data.borrow_mut_data_unchecked() };

    // BUG: No check that caller == current authority!
    // Anyone who signs can change the upgrade authority

    msg!("Setting new upgrade authority (VULNERABLE - no auth check!)");
    
    program_data_data[UPGRADE_AUTHORITY_OFFSET..UPGRADE_AUTHORITY_OFFSET + 32]
        .copy_from_slice(new_authority);

    Ok(())
}
