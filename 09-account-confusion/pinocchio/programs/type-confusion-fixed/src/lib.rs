//! Type Confusion Vulnerability - FIXED
//!
//! SECURE: Verifies account discriminator before processing.

use pinocchio::{
    account_info::AccountInfo,
    entrypoint,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
    ProgramResult,
};

entrypoint!(process_instruction);

const WITHDRAW: u8 = 0;

// Account discriminators (first byte identifies type)
const VAULT_DISCRIMINATOR: u8 = 1;
const USER_DISCRIMINATOR: u8 = 2;
const CONFIG_DISCRIMINATOR: u8 = 3;

// Vault layout
const DISCRIMINATOR_OFFSET: usize = 0;
const VAULT_OWNER_OFFSET: usize = 1;
const VAULT_BALANCE_OFFSET: usize = 33;

pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    if instruction_data.len() < 9 {
        return Err(ProgramError::InvalidInstructionData);
    }

    match instruction_data[0] {
        WITHDRAW => {
            let amount = u64::from_le_bytes(
                instruction_data[1..9].try_into().unwrap(),
            );
            process_withdraw(accounts, amount)
        }
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

/// FIXED: Verifies discriminator before processing
///
/// Security Model:
/// 1. Read first byte as discriminator
/// 2. Verify it matches expected account type
/// 3. Only then proceed with type-specific logic
fn process_withdraw(accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    let [vault, authority] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let vault_data = unsafe { vault.borrow_mut_data_unchecked() };

    // === THE FIX ===
    // Check discriminator first to verify account type
    let discriminator = vault_data[DISCRIMINATOR_OFFSET];
    if discriminator != VAULT_DISCRIMINATOR {
        msg!("Expected Vault (discriminator {}), got {}", 
             VAULT_DISCRIMINATOR, discriminator);
        return Err(ProgramError::InvalidAccountData);
    }

    // Now safe to interpret data as Vault
    let stored_owner = &vault_data[VAULT_OWNER_OFFSET..VAULT_OWNER_OFFSET + 32];
    if stored_owner != authority.key().as_ref() {
        return Err(ProgramError::InvalidAccountData);
    }

    let balance = u64::from_le_bytes(
        vault_data[VAULT_BALANCE_OFFSET..VAULT_BALANCE_OFFSET + 8].try_into().unwrap()
    );

    if balance < amount {
        return Err(ProgramError::InsufficientFunds);
    }

    msg!("Withdrawing {} from verified Vault account", amount);
    Ok(())
}
