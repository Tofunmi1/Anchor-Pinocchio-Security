//! Range Check Vulnerability - Pinocchio Implementation
//!
//! VULNERABLE: No bounds checking on user input.

use pinocchio::{
    account_info::AccountInfo,
    entrypoint,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
    ProgramResult,
};

entrypoint!(process_instruction);

const SET_FEE: u8 = 0;
const SET_MULTIPLIER: u8 = 1;

// Config layout
const FEE_BPS_OFFSET: usize = 0;        // 2 bytes (u16)
const MULTIPLIER_OFFSET: usize = 2;     // 8 bytes (u64)

pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    if instruction_data.len() < 3 {
        return Err(ProgramError::InvalidInstructionData);
    }

    match instruction_data[0] {
        SET_FEE => {
            let fee_bps = u16::from_le_bytes(
                instruction_data[1..3].try_into().unwrap(),
            );
            process_set_fee(accounts, fee_bps)
        }
        SET_MULTIPLIER => {
            let multiplier = u64::from_le_bytes(
                instruction_data[1..9].try_into().unwrap(),
            );
            process_set_multiplier(accounts, multiplier)
        }
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

/// VULNERABLE: No range check on fee
///
/// BUG: Accepts any fee value from 0 to 65535 (655.35%)
/// Attacker with admin access could set fee to 10000 (100%)
fn process_set_fee(accounts: &[AccountInfo], fee_bps: u16) -> ProgramResult {
    let [config, admin] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !admin.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let config_data = unsafe { config.borrow_mut_data_unchecked() };

    // BUG: No validation! Fee could be 100% or more
    config_data[FEE_BPS_OFFSET..FEE_BPS_OFFSET + 2]
        .copy_from_slice(&fee_bps.to_le_bytes());

    msg!("Fee set to {} bps (VULNERABLE - no limit!)", fee_bps);
    Ok(())
}

/// VULNERABLE: No range check on multiplier
fn process_set_multiplier(accounts: &[AccountInfo], multiplier: u64) -> ProgramResult {
    let [config, admin] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !admin.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let config_data = unsafe { config.borrow_mut_data_unchecked() };

    // BUG: No validation! Could overflow in calculations
    config_data[MULTIPLIER_OFFSET..MULTIPLIER_OFFSET + 8]
        .copy_from_slice(&multiplier.to_le_bytes());

    msg!("Multiplier set to {} (VULNERABLE - no limit!)", multiplier);
    Ok(())
}
