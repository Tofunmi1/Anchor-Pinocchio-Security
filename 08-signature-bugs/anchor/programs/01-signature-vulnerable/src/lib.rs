use anchor_lang::prelude::*;

declare_id!("2WkZa747N84M3p6FkAxqSUp5ACTJNX6PfqskmSPtT1BU");

/// # Missing Signer Check Vulnerability
/// 
/// This program demonstrates a critical security flaw where the program verifies
/// an account's public key matches an expected value, but fails to verify that
/// the account actually signed the transaction.
/// 
/// ## Vulnerability Summary
/// 
/// Solana transactions can include accounts in two ways:
/// 1. **Signer** - The account's private key signed the transaction
/// 2. **Non-signer** - The account is just referenced (no signature required)
/// 
/// This program only checks `vault.owner == authority.key()` (address match)
/// but never checks if `authority` actually SIGNED the transaction.
/// 
/// ## Attack Vector
/// 
/// An attacker can:
/// 1. Look up the vault's owner public key (it's on-chain, public data)
/// 2. Include that public key as a non-signing account in their transaction
/// 3. The address check passes, but no signature is verified
/// 4. Attacker gains unauthorized access to owner-only operations

#[program]
pub mod signature_vulnerable {
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
        
        // Transfer SOL from depositor to vault
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
    /// ## Vulnerability: Missing Signer Check
    /// 
    /// This function checks if `authority.key() == vault.owner`, but it NEVER
    /// checks if the `authority` account actually SIGNED the transaction.
    /// 
    /// An attacker can pass the current owner's public key as a non-signing
    /// account, satisfying the address check without having the private key.
    pub fn update_owner(ctx: Context<UpdateOwner>, new_owner: Pubkey) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        let authority = &ctx.accounts.authority;

        // This only checks ADDRESS equality, NOT signature!
        require_keys_eq!(vault.owner, authority.key(), SignatureError::InvalidOwner);
        
        // VULNERABILITY: authority.is_signer is never checked!
        // Any attacker can pass the real owner's pubkey without signing.

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
    /// ## Vulnerability: Missing Signer Check
    /// 
    /// Same issue as `update_owner`. An attacker who has hijacked ownership
    /// can then withdraw all funds.
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        let vault_info = vault.to_account_info();
        let authority_info = ctx.accounts.authority.to_account_info();

        // Address check only - no signature verification!
        require_keys_eq!(vault.owner, authority_info.key(), SignatureError::InvalidOwner);
        require!(vault.balance >= amount, SignatureError::InsufficientFunds);
        
        // VULNERABILITY: authority.is_signer is never checked!

        // Manual lamport transfer from PDA
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
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    
    /// CHECK: VULNERABILITY - This should be Signer<'info> but is UncheckedAccount.
    /// The program checks address equality but never verifies the signature.
    pub authority: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    
    /// CHECK: VULNERABILITY - Missing Signer type.
    /// Attacker can pass owner's pubkey without signing.
    #[account(mut)]
    pub authority: UncheckedAccount<'info>,
    
    pub system_program: Program<'info, System>,
}

// ============================================================================
// Account Structures
// ============================================================================

#[account]
#[derive(InitSpace)]
pub struct Vault {
    /// The current owner who can update ownership and withdraw funds.
    pub owner: Pubkey,
    
    /// Tracked balance (for demonstration purposes).
    pub balance: u64,
    
    /// Original creator used in PDA seeds.
    pub seed_key: Pubkey,
    
    /// PDA bump seed.
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
