//! Type Casting Truncation Vulnerability - FIXED
//!
//! SECURE: Uses try_from for type casting which returns error on overflow.

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

/// FIXED: Uses try_from which returns error on overflow
///
/// Security Model:
/// 1. Perform calculation in u128 to capture full result
/// 2. Use try_from to convert back to u64
/// 3. Return error if result doesn't fit in u64
fn process_calculate(accounts: &[AccountInfo], value_a: u64, value_b: u64) -> ProgramResult {
    let [result_account, caller] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !caller.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Perform multiplication in u128
    let result_u128 = (value_a as u128) * (value_b as u128);

    // === THE FIX ===
    // Use try_from which returns Err if value doesn't fit
    let result = u64::try_from(result_u128).map_err(|_| {
        msg!("Result {} exceeds u64::MAX", result_u128);
        ProgramError::ArithmeticOverflow
    })?;

    msg!("Calculated: {} * {} = {}", value_a, value_b, result);

    let result_data = unsafe { result_account.borrow_mut_data_unchecked() };
    result_data[RESULT_OFFSET..RESULT_OFFSET + 8]
        .copy_from_slice(&result.to_le_bytes());

    Ok(())
}
