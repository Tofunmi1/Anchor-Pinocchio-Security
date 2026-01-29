//! Missing Signer Vulnerability - Pinocchio Implementation
//!
//! VULNERABLE: This program does not check if the authority has signed the transaction.
//! Anyone can withdraw from any vault by simply passing the authority pubkey.

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
const DEPOSIT: u8 = 1;
const WITHDRAW: u8 = 2;

// Vault account layout offsets
const AUTHORITY_OFFSET: usize = 0;
const BALANCE_OFFSET: usize = 32;

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    if instruction_data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }

    match instruction_data[0] {
        INITIALIZE => process_initialize(program_id, accounts),
        DEPOSIT => {
            let amount = u64::from_le_bytes(
                instruction_data[1..9]
                    .try_into()
                    .map_err(|_| ProgramError::InvalidInstructionData)?,
            );
            process_deposit(accounts, amount)
        }
        WITHDRAW => {
            let amount = u64::from_le_bytes(
                instruction_data[1..9]
                    .try_into()
                    .map_err(|_| ProgramError::InvalidInstructionData)?,
            );
            process_withdraw(accounts, amount)
        }
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

/// Initialize a new vault
fn process_initialize(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let [vault, authority, _system_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // Verify authority signed (required for init since they pay)
    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Derive PDA
    let (pda, _bump) = pinocchio::pubkey::find_program_address(
        &[b"vault", authority.key().as_ref()],
        program_id,
    );

    if vault.key() != &pda {
        msg!("Invalid vault PDA");
        return Err(ProgramError::InvalidSeeds);
    }

    // Initialize vault data
    let vault_data = unsafe { vault.borrow_mut_data_unchecked() };
    vault_data[AUTHORITY_OFFSET..AUTHORITY_OFFSET + 32]
        .copy_from_slice(authority.key().as_ref());
    vault_data[BALANCE_OFFSET..BALANCE_OFFSET + 8].copy_from_slice(&0u64.to_le_bytes());

    msg!("Vault initialized for authority");
    Ok(())
}

/// Deposit lamports into the vault
fn process_deposit(accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    let [vault, depositor, _system_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !depositor.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Transfer lamports manually
    unsafe {
        *depositor.borrow_mut_lamports_unchecked() -= amount;
        *vault.borrow_mut_lamports_unchecked() += amount;
    }

    // Update balance
    let vault_data = unsafe { vault.borrow_mut_data_unchecked() };
    let current_balance = u64::from_le_bytes(
        vault_data[BALANCE_OFFSET..BALANCE_OFFSET + 8]
            .try_into()
            .unwrap(),
    );
    let new_balance = current_balance
        .checked_add(amount)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    vault_data[BALANCE_OFFSET..BALANCE_OFFSET + 8].copy_from_slice(&new_balance.to_le_bytes());

    msg!("Deposited lamports");
    Ok(())
}

/// VULNERABLE: Withdraw without signer check!
///
/// BUG: We check that authority matches vault.authority,
/// but we NEVER verify that authority actually SIGNED the transaction!
/// Anyone can pass any pubkey as authority.
fn process_withdraw(accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    let [vault, authority] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    let vault_data = unsafe { vault.borrow_mut_data_unchecked() };

    // Get stored authority
    let stored_authority = &vault_data[AUTHORITY_OFFSET..AUTHORITY_OFFSET + 32];

    // Check authority matches (but NOT if they signed!)
    // VULNERABILITY: This check is useless without verifying signature
    if stored_authority != authority.key().as_ref() {
        msg!("Unauthorized: authority mismatch");
        return Err(ProgramError::InvalidAccountData);
    }

    // NOTE: Missing this critical check!
    // if !authority.is_signer() {
    //     return Err(ProgramError::MissingRequiredSignature);
    // }

    // Get current balance
    let current_balance = u64::from_le_bytes(
        vault_data[BALANCE_OFFSET..BALANCE_OFFSET + 8]
            .try_into()
            .unwrap(),
    );

    if current_balance < amount {
        msg!("Insufficient funds");
        return Err(ProgramError::InsufficientFunds);
    }

    // Update balance
    let new_balance = current_balance.checked_sub(amount).unwrap();
    vault_data[BALANCE_OFFSET..BALANCE_OFFSET + 8].copy_from_slice(&new_balance.to_le_bytes());

    // Transfer lamports
    unsafe {
        *vault.borrow_mut_lamports_unchecked() -= amount;
        *authority.borrow_mut_lamports_unchecked() += amount;
    }

    msg!("Withdrew lamports");
    Ok(())
}
