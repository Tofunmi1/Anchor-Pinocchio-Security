//! Upgrade Authority Vulnerability - FIXED
//!
//! SECURE: Properly verifies caller is the current upgrade authority.

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
const UPGRADE_AUTHORITY_OFFSET: usize = 0;

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

/// FIXED: Verifies caller is current upgrade authority
///
/// Security Model:
/// 1. Verify caller signed the transaction
/// 2. Verify caller's pubkey matches stored upgrade authority
/// 3. Only then allow authority change
fn process_set_authority(accounts: &[AccountInfo], new_authority: &[u8; 32]) -> ProgramResult {
    let [program_data, caller] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !caller.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let program_data_data = unsafe { program_data.borrow_mut_data_unchecked() };

    // === THE FIX ===
    // Verify caller IS the current upgrade authority
    let current_authority = &program_data_data[UPGRADE_AUTHORITY_OFFSET..UPGRADE_AUTHORITY_OFFSET + 32];
    
    if current_authority != caller.key().as_ref() {
        msg!("Caller is not the current upgrade authority");
        return Err(ProgramError::InvalidAccountData);
    }

    msg!("Setting new upgrade authority (verified by current authority)");
    
    program_data_data[UPGRADE_AUTHORITY_OFFSET..UPGRADE_AUTHORITY_OFFSET + 32]
        .copy_from_slice(new_authority);

    Ok(())
}
