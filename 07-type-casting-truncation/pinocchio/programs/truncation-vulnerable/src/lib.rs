//! Type Casting Truncation Vulnerability - Pinocchio Implementation
//!
//! VULNERABLE: Uses `as` keyword for type casting which silently truncates.

use pinocchio::{
    account_info::AccountInfo,
    entrypoint,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
    ProgramResult,
};

entrypoint!(process_instruction);

const CALCULATE: u8 = 0;

// Result layout: result(8)
const RESULT_OFFSET: usize = 0;

pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    if instruction_data.len() < 17 {
        return Err(ProgramError::InvalidInstructionData);
    }

    match instruction_data[0] {
        CALCULATE => {
            let value_a = u64::from_le_bytes(
                instruction_data[1..9].try_into().unwrap(),
            );
            let value_b = u64::from_le_bytes(
                instruction_data[9..17].try_into().unwrap(),
            );
            process_calculate(accounts, value_a, value_b)
        }
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

/// VULNERABLE: Uses `as u64` which silently truncates
///
/// BUG: When multiplying two u64 values, result can exceed u64::MAX.
/// Using `as u64` discards the high bits silently.
fn process_calculate(accounts: &[AccountInfo], value_a: u64, value_b: u64) -> ProgramResult {
    let [result_account, caller] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !caller.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Perform multiplication in u128 to avoid overflow
    let result_u128 = (value_a as u128) * (value_b as u128);

    // BUG: `as u64` silently truncates!
    // If result_u128 = 0x1_0000_0000_0000_0064 (u64::MAX + 100)
    // result becomes 0x64 (100) - massive value loss!
    let result = result_u128 as u64;

    msg!("Calculated: {} * {} = {} (TRUNCATED!)", value_a, value_b, result);
    msg!("Actual result was: {}", result_u128);

    let result_data = unsafe { result_account.borrow_mut_data_unchecked() };
    result_data[RESULT_OFFSET..RESULT_OFFSET + 8]
        .copy_from_slice(&result.to_le_bytes());

    Ok(())
}
