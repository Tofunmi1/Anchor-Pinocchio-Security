use anchor_lang::prelude::*;

declare_id!("mwhX2iLiM9sKJKE3reewCNmCn3BqdDY3uBL5WYn5L5R");

/// # Duplicate Account (Aliasing) Vulnerability
///
/// This program allows the same account to be passed as both source and
/// destination in a transfer, leading to unexpected state mutations.

#[program]
pub mod duplicate_account_vulnerable {
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
    /// ## Vulnerability: Duplicate Account Aliasing
    /// 
    /// The program doesn't check if `from` and `to` reference the same account.
    /// When Anchor deserializes accounts, each gets its own in-memory struct.
    /// 
    /// ## Exploit Scenario (Self-Transfer):
    /// ```
    /// Initial State: Wallet A has balance = 1000
    /// 
    /// 1. Attacker passes Wallet A as BOTH 'from' and 'to'
    /// 2. Anchor deserializes into two separate structs:
    ///    - from = { balance: 1000 }
    ///    - to   = { balance: 1000 }
    /// 
    /// 3. Execute: from.balance -= 100  →  from = { balance: 900 }
    /// 4. Execute: to.balance += 100    →  to   = { balance: 1100 }
    /// 
    /// 5. Anchor serializes both structs back to the SAME account
    ///    - 'from' writes 900
    ///    - 'to' writes 1100 (LAST WRITE WINS)
    /// 
    /// Final State: Wallet A has balance = 1100 (Created 100 out of thin air!)
    /// ```
    pub fn transfer(ctx: Context<Transfer>, amount: u64) -> Result<()> {
        let from = &mut ctx.accounts.from;
        let to = &mut ctx.accounts.to;
        
        // Vulnerability: No duplicate account check
        
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
    // Vulnerability: Both accounts can reference the same address
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
}
