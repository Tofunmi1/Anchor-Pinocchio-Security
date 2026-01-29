//! Range Check Vulnerability - FIXED
//!
//! SECURE: Validates input ranges before accepting.

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

// Validation constants
const MAX_FEE_BPS: u16 = 1000;        // Max 10%
const MAX_MULTIPLIER: u64 = 1_000_000; // Reasonable upper bound

const FEE_BPS_OFFSET: usize = 0;
const MULTIPLIER_OFFSET: usize = 2;

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

/// FIXED: Validates fee is within acceptable range
fn process_set_fee(accounts: &[AccountInfo], fee_bps: u16) -> ProgramResult {
    let [config, admin] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !admin.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // === THE FIX ===
    // Validate fee is within acceptable range
    if fee_bps > MAX_FEE_BPS {
        msg!("Fee {} exceeds maximum {} bps", fee_bps, MAX_FEE_BPS);
        return Err(ProgramError::InvalidArgument);
    }

    let config_data = unsafe { config.borrow_mut_data_unchecked() };
    config_data[FEE_BPS_OFFSET..FEE_BPS_OFFSET + 2]
        .copy_from_slice(&fee_bps.to_le_bytes());

    msg!("Fee set to {} bps (validated)", fee_bps);
    Ok(())
}

/// FIXED: Validates multiplier is within acceptable range
fn process_set_multiplier(accounts: &[AccountInfo], multiplier: u64) -> ProgramResult {
    let [config, admin] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !admin.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // === THE FIX ===
    // Validate multiplier is within acceptable range
    if multiplier == 0 {
        msg!("Multiplier cannot be zero");
        return Err(ProgramError::InvalidArgument);
    }
    if multiplier > MAX_MULTIPLIER {
        msg!("Multiplier {} exceeds maximum {}", multiplier, MAX_MULTIPLIER);
        return Err(ProgramError::InvalidArgument);
    }

    let config_data = unsafe { config.borrow_mut_data_unchecked() };
    config_data[MULTIPLIER_OFFSET..MULTIPLIER_OFFSET + 8]
        .copy_from_slice(&multiplier.to_le_bytes());

    msg!("Multiplier set to {} (validated)", multiplier);
    Ok(())
}
