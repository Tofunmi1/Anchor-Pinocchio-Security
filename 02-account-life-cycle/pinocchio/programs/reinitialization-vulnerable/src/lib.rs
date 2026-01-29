//! Reinitialization Vulnerability - Pinocchio Implementation
//!
//! VULNERABLE: This program does not track initialization state.
//! Anyone can reinitialize an existing account and become the owner.

use pinocchio::{
    account_info::AccountInfo,
    entrypoint,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
    ProgramResult,
};

entrypoint!(process_instruction);

// Instruction discriminators
const INITIALIZE: u8 = 0;
const UPDATE_VALUE: u8 = 1;
const WITHDRAW: u8 = 2;

// Config account layout
const OWNER_OFFSET: usize = 0;       // 32 bytes
const VALUE_OFFSET: usize = 32;      // 8 bytes
const CONFIG_SIZE: usize = 40;

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    if instruction_data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }

    match instruction_data[0] {
        INITIALIZE => {
            let value = u64::from_le_bytes(
                instruction_data[1..9]
                    .try_into()
                    .map_err(|_| ProgramError::InvalidInstructionData)?,
            );
            process_initialize(program_id, accounts, value)
        }
        UPDATE_VALUE => {
            let value = u64::from_le_bytes(
                instruction_data[1..9]
                    .try_into()
                    .map_err(|_| ProgramError::InvalidInstructionData)?,
            );
            process_update_value(accounts, value)
        }
        WITHDRAW => process_withdraw(accounts),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

/// VULNERABLE: Initialize or reinitialize config
///
/// BUG: No check if account is already initialized
/// Anyone call this and overwrite the owner field
fn process_initialize(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    value: u64,
) -> ProgramResult {
    let [config, payer, _system_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !payer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Verify PDA
    let (expected_pda, _bump) =
        pinocchio::pubkey::find_program_address(&[b"config"], program_id);
    if config.key() != &expected_pda {
        return Err(ProgramError::InvalidSeeds);
    }

    // BUG: No check if account has data already!
    // We just overwrite whatever is there
    
    let config_data = unsafe { config.borrow_mut_data_unchecked() };

    // BUG: Always overwrites owner - even if account was already initialized
    // An attacker can call this after the legitimate owner and take over!
    config_data[OWNER_OFFSET..OWNER_OFFSET + 32].copy_from_slice(payer.key().as_ref());
    config_data[VALUE_OFFSET..VALUE_OFFSET + 8].copy_from_slice(&value.to_le_bytes());

    msg!("Config initialized/reinitialized - VULNERABLE!");
    Ok(())
}

/// Update value - checks owner
fn process_update_value(accounts: &[AccountInfo], new_value: u64) -> ProgramResult {
    let [config, owner] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !owner.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let config_data = unsafe { config.borrow_mut_data_unchecked() };
    let stored_owner = &config_data[OWNER_OFFSET..OWNER_OFFSET + 32];

    if stored_owner != owner.key().as_ref() {
        msg!("Not owner");
        return Err(ProgramError::InvalidAccountData);
    }

    config_data[VALUE_OFFSET..VALUE_OFFSET + 8].copy_from_slice(&new_value.to_le_bytes());
    msg!("Value updated");
    Ok(())
}

/// Withdraw - checks owner
fn process_withdraw(accounts: &[AccountInfo]) -> ProgramResult {
    let [config, owner] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !owner.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let config_data = unsafe { config.borrow_data_unchecked() };
    let stored_owner = &config_data[OWNER_OFFSET..OWNER_OFFSET + 32];

    if stored_owner != owner.key().as_ref() {
        msg!("Not owner");
        return Err(ProgramError::InvalidAccountData);
    }

    // Transfer lamports
    let lamports = config.lamports();
    let rent_exempt = 890880; // Approximate
    let withdrawable = lamports.saturating_sub(rent_exempt);

    unsafe {
        *config.borrow_mut_lamports_unchecked() -= withdrawable;
        *owner.borrow_mut_lamports_unchecked() += withdrawable;
    }

    msg!("Withdrew lamports");
    Ok(())
}
