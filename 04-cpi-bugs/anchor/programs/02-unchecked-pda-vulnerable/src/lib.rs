use anchor_lang::prelude::*;

declare_id!("GtPCfUmRmiykmMatihCAkzGT71Rui2KzZdmAZvuhGLxx");

/// # Unchecked PDA Vulnerability
/// 
/// This program fails to verify that a passed account was derived from
/// the expected seeds. It only checks the account's data type (discriminator).

#[program]
pub mod unchecked_pda_vulnerable {
    use super::*;

    /// Creates a new vault for the authority.
    /// 
    /// Note: This instruction does NOT use PDA seeds, allowing accounts
    /// to be created at arbitrary addresses.
    pub fn initialize_vault(ctx: Context<InitializeVault>) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.amount = 100;
        vault.owner = ctx.accounts.authority.key();
        
        emit!(VaultInitialized {
            vault: vault.key(),
            owner: vault.owner,
            amount: vault.amount,
        });
        
        Ok(())
    }

    /// Withdraws funds from a vault.
    /// 
    /// ## Vulnerability: Unchecked PDA Derivation
    /// 
    /// The program verifies `vault.owner == authority`, but fails to verify
    /// that `vault` address was derived from `seeds = [b"vault", authority]`.
    /// 
    /// ## Exploit Scenario:
    /// 1. Attacker creates a Vault at a random keypair address (not a PDA).
    /// 2. Attacker sets `vault.owner = victim.publicKey`.
    /// 3. Attacker (pretending to be victim) calls withdraw with the fake vault.
    /// 4. Program logic operates on the fake vault, potentially:
    ///    - Releasing funds from an unrelated source.
    ///    - Allowing double-spend if the real vault is also usable.
    pub fn withdraw(ctx: Context<Withdraw>) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        require!(vault.owner == ctx.accounts.authority.key(), VaultError::NotOwner);
        require!(vault.amount > 0, VaultError::Empty);
        
        let withdrawn = vault.amount;
        vault.amount = 0;
        
        emit!(Withdrawal {
            vault: vault.key(),
            authority: ctx.accounts.authority.key(),
            amount: withdrawn,
        });
        
        msg!("Withdraw successful from vault: {}", vault.key());
        Ok(())
    }
}

#[derive(Accounts)]
pub struct InitializeVault<'info> {
    // Vulnerability: No `seeds` constraint. Vault can be any keypair.
    #[account(init, payer = authority, space = 8 + Vault::INIT_SPACE)]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    // Vulnerability: No `seeds` constraint to verify canonical PDA.
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}

#[account]
#[derive(InitSpace)]
pub struct Vault {
    pub amount: u64,
    pub owner: Pubkey,
}

#[event]
pub struct VaultInitialized {
    pub vault: Pubkey,
    pub owner: Pubkey,
    pub amount: u64,
}

#[event]
pub struct Withdrawal {
    pub vault: Pubkey,
    pub authority: Pubkey,
    pub amount: u64,
}

#[error_code]
pub enum VaultError {
    #[msg("Caller is not the vault owner.")]
    NotOwner,
    #[msg("Vault is empty.")]
    Empty,
}
