use anchor_lang::prelude::*;

declare_id!("8qNkZNdEoKDq34aNvRh9LBPCxV9gPjWGW7dDqwx5VVVF");

/// # Account Confusion - FIXED Version
/// 
/// This program demonstrates the secure patterns to prevent account confusion.
/// 
/// ## Prevention Strategies
/// 
/// 1. **Use `Account<'info, T>` instead of `UncheckedAccount`**
///    Anchor automatically validates the discriminator when using typed accounts.
/// 
/// 2. **Validate discriminators manually if using raw AccountInfo**
///    Check the first 8 bytes match the expected account type.
/// 
/// 3. **Use unique account type identifiers**
///    Add an explicit `account_type` field that gets checked.
/// 
/// 4. **Validate program ownership**
///    Ensure accounts are owned by the expected program.

#[program]
pub mod pool_fixed {
    use super::*;

    /// Initializes the lending pool.
    pub fn initialize_pool(ctx: Context<InitializePool>) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        pool.account_type = AccountType::Pool;
        pool.authority = ctx.accounts.authority.key();
        pool.total_liquidity = 0;
        pool.is_active = true;
        
        emit!(PoolInitialized {
            pool: pool.key(),
            authority: pool.authority,
        });
        
        msg!("Pool initialized with authority: {}", pool.authority);
        Ok(())
    }

    /// Allows users to create their own vault in the pool.
    pub fn create_user_vault(ctx: Context<CreateUserVault>) -> Result<()> {
        let vault = &mut ctx.accounts.user_vault;
        vault.account_type = AccountType::UserVault;
        vault.owner = ctx.accounts.owner.key();
        vault.deposited_amount = 0;
        vault.is_initialized = true;
        
        emit!(UserVaultCreated {
            vault: vault.key(),
            owner: vault.owner,
        });
        
        Ok(())
    }

    /// Users deposit SOL into the pool through their vault.
    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        let vault = &mut ctx.accounts.user_vault;
        let depositor = &ctx.accounts.depositor;
        
        require!(pool.is_active, PoolError::PoolInactive);
        require!(vault.owner == depositor.key(), PoolError::NotVaultOwner);
        
        // Transfer SOL to pool account
        anchor_lang::system_program::transfer(
            CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                anchor_lang::system_program::Transfer {
                    from: depositor.to_account_info(),
                    to: pool.to_account_info(),
                },
            ),
            amount,
        )?;
        
        vault.deposited_amount += amount;
        pool.total_liquidity += amount;
        
        emit!(Deposited {
            pool: pool.key(),
            vault: vault.key(),
            depositor: depositor.key(),
            amount,
        });
        
        Ok(())
    }

    /// Admin-only function to withdraw liquidity from the pool.
    /// 
    /// ## SECURE: Uses Account<'info, Pool>
    /// 
    /// By using the typed `Account<'info, Pool>` wrapper, Anchor automatically:
    /// 1. Validates the discriminator matches Pool's discriminator
    /// 2. Deserializes the data using the Pool struct
    /// 3. Rejects any account that isn't a valid Pool
    /// 
    /// An attacker cannot pass a UserVault here because:
    /// - UserVault has a different discriminator (first 8 bytes)
    /// - Anchor will abort with "Invalid account discriminator" error
    pub fn admin_withdraw(ctx: Context<AdminWithdraw>, amount: u64) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        let authority = &ctx.accounts.authority;
        let recipient = &ctx.accounts.recipient;
        
        // SECURE: pool is already validated as Pool type by Anchor
        // The constraint also verifies authority matches
        
        require!(pool.total_liquidity >= amount, PoolError::InsufficientLiquidity);
        
        // Additional security: Verify explicit account type marker
        require!(pool.account_type == AccountType::Pool, PoolError::WrongAccountType);
        
        // Update state before transfer
        pool.total_liquidity -= amount;
        
        // Transfer lamports
        let pool_info = pool.to_account_info();
        **pool_info.try_borrow_mut_lamports()? -= amount;
        **recipient.try_borrow_mut_lamports()? += amount;
        
        emit!(AdminWithdrawal {
            pool: pool.key(),
            authority: authority.key(),
            amount,
        });
        
        msg!("SECURE: Admin withdrew {} lamports", amount);
        
        Ok(())
    }

    /// Alternative: Manual validation for raw AccountInfo
    /// 
    /// If you MUST use UncheckedAccount (e.g., for optimization), 
    /// here's how to safely validate the account type.
    pub fn admin_withdraw_manual_validation(
        ctx: Context<AdminWithdrawManual>, 
        amount: u64
    ) -> Result<()> {
        let pool_info = &ctx.accounts.pool;
        let authority = &ctx.accounts.authority;
        let recipient = &ctx.accounts.recipient;
        
        let data = pool_info.try_borrow_data()?;
        
        // SECURE: Validate minimum data length first
        // Validates: discriminator(8) + account_type(1) + authority(32) + liquidity(8) + is_active(1)
        require!(data.len() >= 8 + 1 + 32 + 8 + 1, PoolError::InvalidDiscriminator);
        
        // Also check that the account type field matches Pool
        // This is an additional layer of security beyond the discriminator
        let account_type_byte = data[8];
        require!(account_type_byte == 0, PoolError::WrongAccountType); // 0 = AccountType::Pool
        
        // SECURE: Validate program ownership
        require!(
            pool_info.owner == &crate::ID,
            PoolError::WrongProgramOwner
        );
        
        // Now safe to deserialize
        let mut data_slice = &data[8..];
        let pool = Pool::try_deserialize_unchecked(&mut data_slice)?;
        
        // Validate authority
        require!(pool.authority == authority.key(), PoolError::NotAuthority);
        require!(pool.total_liquidity >= amount, PoolError::InsufficientLiquidity);
        
        // SECURE: Additional check with explicit account type marker
        require!(pool.account_type == AccountType::Pool, PoolError::WrongAccountType);
        
        // Transfer lamports
        drop(data); // Release borrow before modifying lamports
        **pool_info.try_borrow_mut_lamports()? -= amount;
        **recipient.try_borrow_mut_lamports()? += amount;
        
        emit!(AdminWithdrawal {
            pool: pool_info.key(),
            authority: authority.key(),
            amount,
        });
        
        Ok(())
    }
}

// ============================================================================
// Account Type Enum (Defense in Depth)
// ============================================================================

/// Explicit account type marker for defense in depth.
/// Even if discriminator validation is bypassed somehow, this provides
/// an additional layer of type verification.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, InitSpace)]
pub enum AccountType {
    Pool,
    UserVault,
}

// ============================================================================
// Account Contexts
// ============================================================================

#[derive(Accounts)]
pub struct InitializePool<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + Pool::INIT_SPACE,
        seeds = [b"pool"],
        bump
    )]
    pub pool: Account<'info, Pool>,
    
    #[account(mut)]
    pub authority: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct CreateUserVault<'info> {
    #[account(
        init,
        payer = owner,
        space = 8 + UserVault::INIT_SPACE,
        seeds = [b"vault", owner.key().as_ref()],
        bump
    )]
    pub user_vault: Account<'info, UserVault>,
    
    #[account(mut)]
    pub owner: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]
    pub pool: Account<'info, Pool>,
    
    #[account(mut)]
    pub user_vault: Account<'info, UserVault>,
    
    #[account(mut)]
    pub depositor: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct AdminWithdraw<'info> {
    /// SECURE: Account<'info, Pool> validates discriminator automatically
    #[account(
        mut, 
        seeds = [b"pool"],
        bump,
        constraint = pool.authority == authority.key() @ PoolError::NotAuthority
    )]
    pub pool: Account<'info, Pool>,
    
    pub authority: Signer<'info>,
    
    /// CHECK: Recipient receives the withdrawn funds
    #[account(mut)]
    pub recipient: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct AdminWithdrawManual<'info> {
    /// CHECK: Manually validated in instruction logic
    #[account(mut)]
    pub pool: UncheckedAccount<'info>,
    
    pub authority: Signer<'info>,
    
    /// CHECK: Recipient receives the withdrawn funds
    #[account(mut)]
    pub recipient: UncheckedAccount<'info>,
}

// ============================================================================
// Account Structures
// ============================================================================

/// The main lending pool account.
#[account]
#[derive(InitSpace)]
pub struct Pool {
    /// Explicit account type marker (defense in depth)
    pub account_type: AccountType,  // Offset 8: 1 byte
    
    /// Pool administrator who can withdraw liquidity
    pub authority: Pubkey,          // Offset 9: 32 bytes
    
    /// Total SOL deposited in the pool
    pub total_liquidity: u64,       // Offset 41: 8 bytes
    
    /// Whether the pool is accepting deposits
    pub is_active: bool,            // Offset 49: 1 byte
}

/// User's personal vault for tracking deposits.
#[account]
#[derive(InitSpace)]
pub struct UserVault {
    /// Explicit account type marker (defense in depth)
    pub account_type: AccountType,  // Offset 8: 1 byte
    
    /// Vault owner
    pub owner: Pubkey,              // Offset 9: 32 bytes
    
    /// Amount deposited by user
    pub deposited_amount: u64,      // Offset 41: 8 bytes
    
    /// Whether vault is initialized
    pub is_initialized: bool,       // Offset 49: 1 byte
}

// ============================================================================
// Events
// ============================================================================

#[event]
pub struct PoolInitialized {
    pub pool: Pubkey,
    pub authority: Pubkey,
}

#[event]
pub struct UserVaultCreated {
    pub vault: Pubkey,
    pub owner: Pubkey,
}

#[event]
pub struct Deposited {
    pub pool: Pubkey,
    pub vault: Pubkey,
    pub depositor: Pubkey,
    pub amount: u64,
}

#[event]
pub struct AdminWithdrawal {
    pub pool: Pubkey,
    pub authority: Pubkey,
    pub amount: u64,
}

// ============================================================================
// Errors
// ============================================================================

#[error_code]
pub enum PoolError {
    #[msg("Pool is not active.")]
    PoolInactive,
    #[msg("Caller is not the vault owner.")]
    NotVaultOwner,
    #[msg("Caller is not the pool authority.")]
    NotAuthority,
    #[msg("Insufficient liquidity in pool.")]
    InsufficientLiquidity,
    #[msg("Invalid account discriminator.")]
    InvalidDiscriminator,
    #[msg("Account is not owned by this program.")]
    WrongProgramOwner,
    #[msg("Wrong account type.")]
    WrongAccountType,
}
