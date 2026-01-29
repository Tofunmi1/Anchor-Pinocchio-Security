use anchor_lang::prelude::*;

declare_id!("9pMkZNdEoKDq34aNvRh9LBPCxV9gPjWGW7dDqwx5VVVb");

/// # Account Confusion Vulnerability ($50M Bug Class)
/// 
/// This program demonstrates a critical vulnerability where an attacker can
/// exploit overlapping memory layouts between different account types to
/// manipulate program behavior and steal funds.
/// 
/// ## Background: The $50M Bug Class
/// 
/// Account confusion has been responsible for some of the largest exploits
/// in Solana's history, including the $52M Cashio hack. The vulnerability
/// occurs when a program fails to properly validate that an account is of
/// the expected type before deserializing and using its data.
/// 
/// ## Vulnerability Summary
/// 
/// This protocol has two account types with similar memory layouts:
/// 
/// ```
/// Pool Account:
/// ┌─────────────────────────────────────────────────────────────────────────┐
/// │ Offset │ Size │ Field            │ Description                         │
/// ├────────┼──────┼──────────────────┼─────────────────────────────────────┤
/// │ 0      │ 8    │ Discriminator    │ Anchor type identifier              │
/// │ 8      │ 32   │ authority        │ Pool admin who can withdraw         │
/// │ 40     │ 8    │ total_liquidity  │ Total SOL in the pool               │
/// │ 48     │ 1    │ is_active        │ Whether pool accepts deposits       │
/// └─────────────────────────────────────────────────────────────────────────┘
/// 
/// UserVault Account (ATTACKER CONTROLLED):
/// ┌─────────────────────────────────────────────────────────────────────────┐
/// │ Offset │ Size │ Field            │ Maps to in Pool                     │
/// ├────────┼──────┼──────────────────┼─────────────────────────────────────┤
/// │ 0      │ 8    │ Discriminator    │ (Different from Pool)               │
/// │ 8      │ 32   │ owner            │ authority (ATTACKER'S PUBKEY!)      │
/// │ 40     │ 8    │ deposited_amount │ total_liquidity                     │
/// │ 48     │ 1    │ is_initialized   │ is_active                           │
/// └─────────────────────────────────────────────────────────────────────────┘
/// ```
/// 
/// ## The Attack
/// 
/// 1. Attacker creates a UserVault with their pubkey as `owner`
/// 2. Attacker calls `admin_withdraw` but passes their UserVault as "pool"
/// 3. Program deserializes UserVault data using Pool layout
/// 4. UserVault.owner (attacker) is read as Pool.authority
/// 5. Authority check passes -> Attacker drains all funds!

#[program]
pub mod pool_vulnerable {
    use super::*;

    /// Initializes the lending pool.
    pub fn initialize_pool(ctx: Context<InitializePool>) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
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
    /// ## VULNERABILITY: Account Type Confusion
    /// 
    /// This function accepts a generic AccountInfo for the "pool" parameter
    /// and manually deserializes it. The vulnerability is that it ONLY checks
    /// if the deserialized `authority` matches the signer, but it NEVER
    /// validates that the account is actually a Pool account.
    /// 
    /// An attacker can pass their UserVault instead of the Pool:
    /// - UserVault.owner (offset 8) is read as Pool.authority
    /// - If attacker's pubkey is at offset 8, they become the "authority"
    /// - Authority check passes -> Funds are stolen!
    pub fn admin_withdraw(ctx: Context<AdminWithdraw>, amount: u64) -> Result<()> {
        let pool_info = &ctx.accounts.pool;
        let authority = &ctx.accounts.authority;
        let recipient = &ctx.accounts.recipient;
        
        // VULNERABLE: Manual deserialization without type validation!
        // We skip the 8-byte discriminator and deserialize as Pool
        let data = pool_info.try_borrow_data()?;
        
        // Check minimum data length (discriminator + authority + liquidity + flag)
        require!(data.len() >= 8 + 32 + 8 + 1, PoolError::InvalidAccountData);
        
        // Skip discriminator (8 bytes) - THIS IS THE BUG!
        // We should validate the discriminator matches Pool, but we don't!
        let authority_bytes: [u8; 32] = data[8..40].try_into().unwrap();
        let pool_authority = Pubkey::from(authority_bytes);
        
        let liquidity_bytes: [u8; 8] = data[40..48].try_into().unwrap();
        let total_liquidity = u64::from_le_bytes(liquidity_bytes);
        
        // Check that caller is the "authority" (but this reads from wrong account!)
        require!(pool_authority == authority.key(), PoolError::NotAuthority);
        require!(total_liquidity >= amount, PoolError::InsufficientLiquidity);
        
        // Transfer lamports
        **pool_info.try_borrow_mut_lamports()? -= amount;
        **recipient.try_borrow_mut_lamports()? += amount;
        
        emit!(AdminWithdrawal {
            pool: pool_info.key(),
            authority: authority.key(),
            amount,
        });
        
        msg!("VULNERABLE: Admin withdrew {} lamports", amount);
        
        Ok(())
    }
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
    /// CHECK: VULNERABILITY - This should be Account<'info, Pool>
    /// Using UncheckedAccount allows ANY account to be passed!
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
    /// Pool administrator who can withdraw liquidity
    pub authority: Pubkey,       // Offset 8: 32 bytes
    
    /// Total SOL deposited in the pool
    pub total_liquidity: u64,    // Offset 40: 8 bytes
    
    /// Whether the pool is accepting deposits
    pub is_active: bool,         // Offset 48: 1 byte
}

/// User's personal vault for tracking deposits.
/// 
/// ## DANGER: Memory Layout Overlap
/// 
/// This struct has the SAME memory layout as Pool after the discriminator:
/// - owner (32 bytes) aligns with Pool.authority
/// - deposited_amount (8 bytes) aligns with Pool.total_liquidity
/// - is_initialized (1 byte) aligns with Pool.is_active
/// 
/// If the program doesn't validate account types, UserVault can be
/// interpreted as Pool, with owner becoming authority!
#[account]
#[derive(InitSpace)]
pub struct UserVault {
    /// Vault owner (ATTACKER'S PUBKEY)
    pub owner: Pubkey,           // Offset 8: 32 bytes (maps to Pool.authority!)
    
    /// Amount deposited by user
    pub deposited_amount: u64,   // Offset 40: 8 bytes (maps to Pool.total_liquidity!)
    
    /// Whether vault is initialized
    pub is_initialized: bool,    // Offset 48: 1 byte (maps to Pool.is_active!)
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
    #[msg("Invalid account data.")]
    InvalidAccountData,
}
