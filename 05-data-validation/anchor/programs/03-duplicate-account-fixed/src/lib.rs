use anchor_lang::prelude::*;

declare_id!("FRwiTLfEffh9jMEvijPPUPdpuF9Q4ieiGvJJmeWc3in5");

/// # Secure: Duplicate Account Prevention
///
/// This program validates that mutable accounts are distinct before
/// processing, preventing self-transfer exploits.

#[program]
pub mod duplicate_account_fixed {
    use super::*;

    /// Initializes a new wallet with a starting balance.
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        ctx.accounts.wallet.balance = 1000;
        
        emit!(WalletCreated {
            wallet: ctx.accounts.wallet.key(),
            owner: ctx.accounts.signer.key(),
            balance: 1000,
        });
        
        Ok(())
    }

    /// Transfers points from one wallet to another.
    /// 
    /// ## Secure Pattern: Account Uniqueness Validation
    /// 
    /// Before processing, the program verifies that the source and
    /// destination accounts are different. This prevents:
    /// - Self-transfer exploits (infinite money glitch)
    /// - Aliasing bugs from duplicate AccountInfo references
    /// - Unexpected state due to last-write-wins serialization
    pub fn transfer(ctx: Context<Transfer>, amount: u64) -> Result<()> {
        let from = &mut ctx.accounts.from;
        let to = &mut ctx.accounts.to;
        
        // Secure: Ensure accounts are distinct
        require_keys_neq!(from.key(), to.key(), WalletError::DuplicateAccount);
        
        require!(from.balance >= amount, WalletError::InsufficientFunds);
        
        from.balance -= amount;
        to.balance += amount;
        
        emit!(TransferExecuted {
            from: from.key(),
            to: to.key(),
            amount,
        });
        
        msg!("Transferred {} from {} to {}", amount, from.key(), to.key());
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = signer, space = 8 + Wallet::INIT_SPACE)]
    pub wallet: Account<'info, Wallet>,
    #[account(mut)]
    pub signer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Transfer<'info> {
    #[account(mut)]
    pub from: Account<'info, Wallet>,
    #[account(mut)]
    pub to: Account<'info, Wallet>,
}

#[account]
#[derive(InitSpace)]
pub struct Wallet {
    pub balance: u64,
}

#[event]
pub struct WalletCreated {
    pub wallet: Pubkey,
    pub owner: Pubkey,
    pub balance: u64,
}

#[event]
pub struct TransferExecuted {
    pub from: Pubkey,
    pub to: Pubkey,
    pub amount: u64,
}

#[error_code]
pub enum WalletError {
    #[msg("Insufficient balance for transfer.")]
    InsufficientFunds,
    #[msg("Source and destination accounts must be different.")]
    DuplicateAccount,
}
