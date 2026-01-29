//! Reinitialization Vulnerability - FIXED
//!
//! SECURE: This program tracks initialization state and prevents
//! reinitialization by a different owner.

use pinocchio::{
    account_info::AccountInfo,
    entrypoint,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
    ProgramResult,
};

entrypoint!(process_instruction);

const INITIALIZE: u8 = 0;
const UPDATE_VALUE: u8 = 1;
const WITHDRAW: u8 = 2;

// Config account layout - with is_initialized flag
const IS_INITIALIZED_OFFSET: usize = 0;  // 1 byte
const OWNER_OFFSET: usize = 1;           // 32 bytes
const VALUE_OFFSET: usize = 33;          // 8 bytes
const CONFIG_SIZE: usize = 41;

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

/// FIXED: Initialize with is_initialized check
///
/// Security Model:
/// 1. Check is_initialized flag first
/// 2. If already initialized, reject (or verify caller is owner)
/// 3. Only set owner on first initialization
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

    let config_data = unsafe { config.borrow_mut_data_unchecked() };

    // === THE FIX ===
    // Check if account is already initialized
    let is_initialized = config_data[IS_INITIALIZED_OFFSET] != 0;

    if is_initialized {
        // Account exists - verify caller is the original owner
        let stored_owner = &config_data[OWNER_OFFSET..OWNER_OFFSET + 32];
        
        if stored_owner != payer.key().as_ref() {
            msg!("Account already initialized by different owner");
            return Err(ProgramError::AccountAlreadyInitialized);
        }
        
        // Owner matches - only allow value update, NOT owner change
        config_data[VALUE_OFFSET..VALUE_OFFSET + 8].copy_from_slice(&value.to_le_bytes());
        msg!("Value updated by owner");
    } else {
        // First initialization - set all fields
        config_data[IS_INITIALIZED_OFFSET] = 1; // Mark as initialized
        config_data[OWNER_OFFSET..OWNER_OFFSET + 32].copy_from_slice(payer.key().as_ref());
        config_data[VALUE_OFFSET..VALUE_OFFSET + 8].copy_from_slice(&value.to_le_bytes());
        msg!("Config initialized for first time");
    }

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

    // Check initialized
    if config_data[IS_INITIALIZED_OFFSET] == 0 {
        msg!("Account not initialized");
        return Err(ProgramError::UninitializedAccount);
    }

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

    // Check initialized
    if config_data[IS_INITIALIZED_OFFSET] == 0 {
        msg!("Account not initialized");
        return Err(ProgramError::UninitializedAccount);
    }

    let stored_owner = &config_data[OWNER_OFFSET..OWNER_OFFSET + 32];
    if stored_owner != owner.key().as_ref() {
        msg!("Not owner");
        return Err(ProgramError::InvalidAccountData);
    }

    // Transfer lamports
    let lamports = config.lamports();
    let rent_exempt = 890880;
    let withdrawable = lamports.saturating_sub(rent_exempt);

    unsafe {
        *config.borrow_mut_lamports_unchecked() -= withdrawable;
        *owner.borrow_mut_lamports_unchecked() += withdrawable;
    }

    msg!("Withdrew lamports");
    Ok(())
}
