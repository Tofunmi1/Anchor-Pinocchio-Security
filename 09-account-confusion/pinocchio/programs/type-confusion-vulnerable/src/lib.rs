//! Type Confusion Vulnerability - Pinocchio Implementation
//!
//! VULNERABLE: Does not verify account type/discriminator.

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

// Vault layout (what we expect)
const VAULT_DISCRIMINATOR: u8 = 1;
const VAULT_OWNER_OFFSET: usize = 1;
const VAULT_BALANCE_OFFSET: usize = 33;

// User layout (attacker's account type)
// Same offsets but different semantics!
const USER_DISCRIMINATOR: u8 = 2;

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

/// VULNERABLE: Does not check discriminator
///
/// BUG: Any account owned by Program can be passed.
/// Attacker can pass a User account instead of Vault account.
/// The bytes at the same offsets mean different things!
fn process_withdraw(accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    let [vault, authority] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let vault_data = unsafe { vault.borrow_mut_data_unchecked() };

    // BUG: No discriminator check!
    // We assume this is a Vault, but it could be any account type

    // Read owner (bytes 1-32)
    let stored_owner = &vault_data[VAULT_OWNER_OFFSET..VAULT_OWNER_OFFSET + 32];
    if stored_owner != authority.key().as_ref() {
        return Err(ProgramError::InvalidAccountData);
    }

    // Read balance (bytes 33-40)
    let balance = u64::from_le_bytes(
        vault_data[VAULT_BALANCE_OFFSET..VAULT_BALANCE_OFFSET + 8].try_into().unwrap()
    );

    if balance < amount {
        return Err(ProgramError::InsufficientFunds);
    }

    // Proceed with withdrawal (VULNERABLE - might not be a vault!)
    msg!("Withdrawing {} from account (type not verified!)", amount);
    Ok(())
}
