//! Missing Signer Vulnerability - FIXED
//!
//! SECURE: This program correctly verifies that the authority has signed
//! the transaction before allowing withdrawal.

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
const DEPOSIT: u8 = 1;
const WITHDRAW: u8 = 2;

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

fn process_initialize(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let [vault, authority, _system_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // Verify authority signed
    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Derive and verify PDA
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

    msg!("Vault initialized");
    Ok(())
}

fn process_deposit(accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    let [vault, depositor, _system_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !depositor.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Transfer lamports
    unsafe {
        *depositor.borrow_mut_lamports_unchecked() -= amount;
        *vault.borrow_mut_lamports_unchecked() += amount;
    }

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

    msg!("Deposited");
    Ok(())
}

/// FIXED: Withdraw WITH proper signer verification
///
/// Security Model:
/// 1. Verify authority.is_signer() - proves they own the private key
/// 2. Verify authority matches vault.authority - proves they own this vault
/// 3. Check sufficient balance - prevents overdraw
fn process_withdraw(accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    let [vault, authority] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // === THE FIX ===
    // Verify authority actually SIGNED this transaction
    // Without this, anyone can claim to be the authority
    if !authority.is_signer() {
        msg!("Authority must sign the transaction");
        return Err(ProgramError::MissingRequiredSignature);
    }

    let vault_data = unsafe { vault.borrow_mut_data_unchecked() };

    // Verify authority matches stored authority
    let stored_authority = &vault_data[AUTHORITY_OFFSET..AUTHORITY_OFFSET + 32];
    if stored_authority != authority.key().as_ref() {
        msg!("Unauthorized: not the vault owner");
        return Err(ProgramError::InvalidAccountData);
    }

    // Check balance
    let current_balance = u64::from_le_bytes(
        vault_data[BALANCE_OFFSET..BALANCE_OFFSET + 8]
            .try_into()
            .unwrap(),
    );

    if current_balance < amount {
        msg!("Insufficient funds");
        return Err(ProgramError::InsufficientFunds);
    }

    // Update balance (effects before interactions)
    let new_balance = current_balance
        .checked_sub(amount)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    vault_data[BALANCE_OFFSET..BALANCE_OFFSET + 8].copy_from_slice(&new_balance.to_le_bytes());

    // Transfer lamports
    unsafe {
        *vault.borrow_mut_lamports_unchecked() -= amount;
        *authority.borrow_mut_lamports_unchecked() += amount;
    }

    msg!("Withdrew lamports");
    Ok(())
}
