use anchor_lang::prelude::*;

declare_id!("HBt23tJuKg6BgXvMPNamX64FbeVkFSaBVSDm1eTf3Gpf");

/// # Secure: Proper Signer Verification
/// 
/// This program demonstrates the correct way to verify that an account has
/// actually signed a transaction before granting access to privileged operations.
/// 
/// ## Fix: Using Anchor's Signer Type
/// 
/// Anchor's `Signer<'info>` type automatically enforces that the account:
/// 1. Is marked as a signer in the transaction
/// 2. Has a valid signature from the account's private key
/// 
/// If the signature is missing or invalid, the transaction fails before
/// the instruction logic even begins to execute.

#[program]
pub mod signature_fixed {
    use super::*;

    /// Creates a new vault owned by the signer.
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.owner = ctx.accounts.signer.key();
        vault.balance = 0;
        vault.seed_key = ctx.accounts.signer.key();
        vault.bump = ctx.bumps.vault;
        
        emit!(VaultCreated {
            vault: vault.key(),
            owner: vault.owner,
        });
        
        Ok(())
    }

    /// Deposits SOL into the vault.
    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        let depositor = &ctx.accounts.depositor;
        
        anchor_lang::system_program::transfer(
            CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                anchor_lang::system_program::Transfer {
                    from: depositor.to_account_info(),
                    to: vault.to_account_info(),
                },
            ),
            amount,
        )?;
        
        vault.balance += amount;
        
        emit!(Deposited {
            vault: vault.key(),
            depositor: depositor.key(),
            amount,
        });
        
        Ok(())
    }

    /// Updates the vault owner to a new address.
    /// 
    /// ## Secure Pattern
    /// 
    /// The `authority` account is typed as `Signer<'info>`, which means:
    /// 1. The transaction MUST include a valid signature from this account
    /// 2. Without the owner's private key, no one can sign for this account
    /// 3. The constraint `vault.owner == authority.key()` ensures only the
    ///    current owner can authorize ownership transfer
    pub fn update_owner(ctx: Context<UpdateOwner>, new_owner: Pubkey) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        // SECURE: authority is Signer<'info>, so we know they signed!
        // The constraint in Accounts struct ensures authority == vault.owner
        
        let old_owner = vault.owner;
        vault.owner = new_owner;
        
        emit!(OwnerUpdated {
            vault: vault.key(),
            old_owner,
            new_owner,
        });
        
        Ok(())
    }

    /// Withdraws SOL from the vault to the authority.
    /// 
    /// ## Secure Pattern
    /// 
    /// Same as `update_owner`: the `Signer<'info>` type ensures that only
    /// someone with the owner's private key can withdraw funds.
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        let vault_info = vault.to_account_info();
        let authority_info = ctx.accounts.authority.to_account_info();

        require!(vault.balance >= amount, SignatureError::InsufficientFunds);
        
        // SECURE: We know authority signed because of Signer<'info> type
        // No explicit is_signer check needed - Anchor handles it

        **vault_info.try_borrow_mut_lamports()? -= amount;
        **authority_info.try_borrow_mut_lamports()? += amount;
        
        vault.balance -= amount;
        
        emit!(Withdrawn {
            vault: vault.key(),
            authority: authority_info.key(),
            amount,
        });
        
        Ok(())
    }
}

// ============================================================================
// Account Contexts
// ============================================================================

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init, 
        payer = signer, 
        space = 8 + Vault::INIT_SPACE,
        seeds = [b"vault", signer.key().as_ref()],
        bump
    )]
    pub vault: Account<'info, Vault>,
    
    #[account(mut)]
    pub signer: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    
    #[account(mut)]
    pub depositor: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UpdateOwner<'info> {
    /// The vault with ownership constraint.
    #[account(mut, constraint = vault.owner == authority.key() @ SignatureError::InvalidOwner)]
    pub vault: Account<'info, Vault>,
    
    /// SECURE: Signer<'info> enforces signature verification.
    /// Without the owner's private key, this transaction will fail.
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    /// The vault with ownership constraint.
    #[account(mut, constraint = vault.owner == authority.key() @ SignatureError::InvalidOwner)]
    pub vault: Account<'info, Vault>,
    
    /// SECURE: Signer<'info> enforces signature verification.
    #[account(mut)]
    pub authority: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

// ============================================================================
// Account Structures
// ============================================================================

#[account]
#[derive(InitSpace)]
pub struct Vault {
    pub owner: Pubkey,
    pub balance: u64,
    pub seed_key: Pubkey,
    pub bump: u8,
}

// ============================================================================
// Events
// ============================================================================

#[event]
pub struct VaultCreated {
    pub vault: Pubkey,
    pub owner: Pubkey,
}

#[event]
pub struct Deposited {
    pub vault: Pubkey,
    pub depositor: Pubkey,
    pub amount: u64,
}

#[event]
pub struct OwnerUpdated {
    pub vault: Pubkey,
    pub old_owner: Pubkey,
    pub new_owner: Pubkey,
}

#[event]
pub struct Withdrawn {
    pub vault: Pubkey,
    pub authority: Pubkey,
    pub amount: u64,
}

// ============================================================================
// Errors
// ============================================================================

#[error_code]
pub enum SignatureError {
    #[msg("Authority does not match vault owner.")]
    InvalidOwner,
    #[msg("Insufficient funds in vault.")]
    InsufficientFunds,
}
