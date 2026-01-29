//! Integer Overflow Vulnerability - Pinocchio Implementation
//!
//! VULNERABLE: Uses wrapping arithmetic which silently overflows/underflows.

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
const STAKE: u8 = 1;
const WITHDRAW: u8 = 2;

// Pool layout: authority(32) + total_staked(8) + reward_rate(8)
const AUTHORITY_OFFSET: usize = 0;
const TOTAL_STAKED_OFFSET: usize = 32;
const REWARD_RATE_OFFSET: usize = 40;

// User stake layout: staked_amount(8)
const STAKED_AMOUNT_OFFSET: usize = 0;

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    if instruction_data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }

    match instruction_data[0] {
        INITIALIZE => process_initialize(accounts),
        STAKE => {
            let amount = u64::from_le_bytes(
                instruction_data[1..9].try_into().unwrap(),
            );
            process_stake(accounts, amount)
        }
        WITHDRAW => {
            let amount = u64::from_le_bytes(
                instruction_data[1..9].try_into().unwrap(),
            );
            process_withdraw(accounts, amount)
        }
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

fn process_initialize(accounts: &[AccountInfo]) -> ProgramResult {
    let [pool, authority, _system] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let pool_data = unsafe { pool.borrow_mut_data_unchecked() };
    pool_data[AUTHORITY_OFFSET..AUTHORITY_OFFSET + 32]
        .copy_from_slice(authority.key().as_ref());
    pool_data[TOTAL_STAKED_OFFSET..TOTAL_STAKED_OFFSET + 8]
        .copy_from_slice(&0u64.to_le_bytes());
    pool_data[REWARD_RATE_OFFSET..REWARD_RATE_OFFSET + 8]
        .copy_from_slice(&100u64.to_le_bytes());

    msg!("Pool initialized");
    Ok(())
}

/// VULNERABLE: Uses wrapping_add which silently overflows
fn process_stake(accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    let [pool, user_stake, staker, _system] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !staker.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let pool_data = unsafe { pool.borrow_mut_data_unchecked() };
    let user_data = unsafe { user_stake.borrow_mut_data_unchecked() };

    // Read current values
    let total_staked = u64::from_le_bytes(
        pool_data[TOTAL_STAKED_OFFSET..TOTAL_STAKED_OFFSET + 8].try_into().unwrap()
    );
    let staked_amount = u64::from_le_bytes(
        user_data[STAKED_AMOUNT_OFFSET..STAKED_AMOUNT_OFFSET + 8].try_into().unwrap()
    );

    // BUG: Wrapping add - overflows silently!
    // If total_staked = u64::MAX - 100 and amount = 200
    // Result wraps to 99 instead of failing
    let new_total = total_staked.wrapping_add(amount);
    let new_staked = staked_amount.wrapping_add(amount);

    // Write new values
    pool_data[TOTAL_STAKED_OFFSET..TOTAL_STAKED_OFFSET + 8]
        .copy_from_slice(&new_total.to_le_bytes());
    user_data[STAKED_AMOUNT_OFFSET..STAKED_AMOUNT_OFFSET + 8]
        .copy_from_slice(&new_staked.to_le_bytes());

    msg!("Staked: {}. Total: {}", amount, new_total);
    Ok(())
}

/// VULNERABLE: Uses wrapping_sub which silently underflows
fn process_withdraw(accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    let [pool, user_stake, staker] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !staker.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let pool_data = unsafe { pool.borrow_mut_data_unchecked() };
    let user_data = unsafe { user_stake.borrow_mut_data_unchecked() };

    let total_staked = u64::from_le_bytes(
        pool_data[TOTAL_STAKED_OFFSET..TOTAL_STAKED_OFFSET + 8].try_into().unwrap()
    );
    let staked_amount = u64::from_le_bytes(
        user_data[STAKED_AMOUNT_OFFSET..STAKED_AMOUNT_OFFSET + 8].try_into().unwrap()
    );

    // BUG: Wrapping sub - underflows silently!
    // If staked_amount = 50 and amount = 100
    // Result wraps to u64::MAX - 49 instead of failing
    let new_staked = staked_amount.wrapping_sub(amount);
    let new_total = total_staked.wrapping_sub(amount);

    pool_data[TOTAL_STAKED_OFFSET..TOTAL_STAKED_OFFSET + 8]
        .copy_from_slice(&new_total.to_le_bytes());
    user_data[STAKED_AMOUNT_OFFSET..STAKED_AMOUNT_OFFSET + 8]
        .copy_from_slice(&new_staked.to_le_bytes());

    msg!("Withdrew: {}. Remaining: {}", amount, new_staked);
    Ok(())
}
