use anchor_lang::prelude::*;
use anchor_spl::token::{self, Mint, Token, TokenAccount, Transfer};

declare_id!("Amm1VuLnErabLe111111111111111111111111111111");

/// ⚠️ VULNERABLE AMM - Contains 8 Security Bugs
/// 
/// This program implements a constant product AMM (x * y = k) with
/// intentional vulnerabilities for educational purposes.
/// 
/// BUGS:
/// 01. Missing slippage protection in swap
/// 02. Integer overflow in K calculation
/// 03. Spot price oracle (manipulable)
/// 04. Missing signer check on withdraw
/// 05. Fee calculation rounding error
/// 06. State update after external call (reentrancy pattern)
/// 07. Missing owner check on pool (UncheckedAccount)
/// 08. Unprotected initialize (no PDA seeds)

const FEE_BPS: u64 = 30; // 0.3% fee (30 basis points)

#[program]
pub mod amm_vulnerable {
    use super::*;

    /// ⚠️ BUG #8: Unprotected Initialize
    /// No PDA seeds - anyone can create pools, front-run initialization
    pub fn initialize(
        ctx: Context<Initialize>,
        fee_bps: u64,
    ) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        
        // First caller becomes authority - can be front-run!
        pool.authority = ctx.accounts.authority.key();
        pool.token_a_mint = ctx.accounts.token_a_mint.key();
        pool.token_b_mint = ctx.accounts.token_b_mint.key();
        pool.token_a_vault = ctx.accounts.token_a_vault.key();
        pool.token_b_vault = ctx.accounts.token_b_vault.key();
        pool.lp_mint = ctx.accounts.lp_mint.key();
        pool.reserve_a = 0;
        pool.reserve_b = 0;
        pool.total_lp_supply = 0;
        pool.fee_bps = fee_bps;
        // BUG: No TWAP tracking
        pool.last_update = 0;
        pool.price_cumulative = 0;

        msg!("Pool initialized with fee: {} bps", fee_bps);
        Ok(())
    }

    /// Add liquidity to the pool
    pub fn add_liquidity(
        ctx: Context<AddLiquidity>,
        amount_a: u64,
        amount_b: u64,
    ) -> Result<()> {
        let pool = &mut ctx.accounts.pool;

        // Transfer tokens to vaults
        token::transfer(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.user_token_a.to_account_info(),
                    to: ctx.accounts.token_a_vault.to_account_info(),
                    authority: ctx.accounts.user.to_account_info(),
                },
            ),
            amount_a,
        )?;

        token::transfer(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.user_token_b.to_account_info(),
                    to: ctx.accounts.token_b_vault.to_account_info(),
                    authority: ctx.accounts.user.to_account_info(),
                },
            ),
            amount_b,
        )?;

        // Calculate LP tokens to mint
        let lp_tokens = if pool.total_lp_supply == 0 {
            // ⚠️ BUG #2: Potential overflow with large initial liquidity
            // sqrt(amount_a * amount_b) can overflow
            let k = amount_a * amount_b; // VULNERABLE: u64 overflow!
            integer_sqrt(k)
        } else {
            // Proportional to existing liquidity
            let lp_a = (amount_a as u128 * pool.total_lp_supply as u128 / pool.reserve_a as u128) as u64;
            let lp_b = (amount_b as u128 * pool.total_lp_supply as u128 / pool.reserve_b as u128) as u64;
            std::cmp::min(lp_a, lp_b)
        };

        // Mint LP tokens
        let seeds = &[
            b"pool".as_ref(),
            pool.token_a_mint.as_ref(),
            pool.token_b_mint.as_ref(),
            &[ctx.bumps.pool],
        ];
        let signer_seeds = &[&seeds[..]];

        token::mint_to(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                token::MintTo {
                    mint: ctx.accounts.lp_mint.to_account_info(),
                    to: ctx.accounts.user_lp_account.to_account_info(),
                    authority: pool.to_account_info(),
                },
                signer_seeds,
            ),
            lp_tokens,
        )?;

        // Update reserves
        pool.reserve_a += amount_a;
        pool.reserve_b += amount_b;
        pool.total_lp_supply += lp_tokens;

        msg!("Added liquidity: {} A, {} B -> {} LP", amount_a, amount_b, lp_tokens);
        Ok(())
    }

    /// ⚠️ BUG #4: Missing Signer Check on Withdraw
    /// Anyone can call this with any LP owner's pubkey!
    pub fn remove_liquidity(
        ctx: Context<RemoveLiquidity>,
        lp_amount: u64,
    ) -> Result<()> {
        let pool = &mut ctx.accounts.pool;

        // Calculate tokens to return
        let amount_a = (lp_amount as u128 * pool.reserve_a as u128 / pool.total_lp_supply as u128) as u64;
        let amount_b = (lp_amount as u128 * pool.reserve_b as u128 / pool.total_lp_supply as u128) as u64;

        // Burn LP tokens
        token::burn(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                token::Burn {
                    mint: ctx.accounts.lp_mint.to_account_info(),
                    from: ctx.accounts.user_lp_account.to_account_info(),
                    authority: ctx.accounts.lp_owner.to_account_info(), // BUG: Not verified as signer!
                },
            ),
            lp_amount,
        )?;

        // Transfer tokens back
        let seeds = &[
            b"pool".as_ref(),
            pool.token_a_mint.as_ref(),
            pool.token_b_mint.as_ref(),
            &[ctx.bumps.pool],
        ];
        let signer_seeds = &[&seeds[..]];

        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.token_a_vault.to_account_info(),
                    to: ctx.accounts.user_token_a.to_account_info(),
                    authority: pool.to_account_info(),
                },
                signer_seeds,
            ),
            amount_a,
        )?;

        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.token_b_vault.to_account_info(),
                    to: ctx.accounts.user_token_b.to_account_info(),
                    authority: pool.to_account_info(),
                },
                signer_seeds,
            ),
            amount_b,
        )?;

        // Update reserves
        pool.reserve_a -= amount_a;
        pool.reserve_b -= amount_b;
        pool.total_lp_supply -= lp_amount;

        msg!("Removed liquidity: {} LP -> {} A, {} B", lp_amount, amount_a, amount_b);
        Ok(())
    }

    /// ⚠️ BUGS #1, #5, #6: Multiple vulnerabilities in swap
    pub fn swap(
        ctx: Context<Swap>,
        amount_in: u64,
        is_a_to_b: bool,
        // BUG #1: No min_amount_out parameter for slippage protection!
    ) -> Result<()> {
        let pool = &mut ctx.accounts.pool;

        let (reserve_in, reserve_out) = if is_a_to_b {
            (pool.reserve_a, pool.reserve_b)
        } else {
            (pool.reserve_b, pool.reserve_a)
        };

        // ⚠️ BUG #5: Fee calculation rounds DOWN - can be 0 for small amounts
        let fee = amount_in * pool.fee_bps / 10000; // 99 * 30 / 10000 = 0!
        let amount_in_after_fee = amount_in - fee;

        // ⚠️ BUG #2: Potential overflow in K calculation
        let k = reserve_in * reserve_out; // Can overflow!
        
        // Calculate output using constant product formula
        let new_reserve_in = reserve_in + amount_in_after_fee;
        let new_reserve_out = k / new_reserve_in;
        let amount_out = reserve_out - new_reserve_out;

        // ⚠️ BUG #1: No slippage check!
        // Missing: require!(amount_out >= min_amount_out, AmmError::SlippageExceeded);

        // ⚠️ BUG #6: External calls BEFORE state update (reentrancy pattern)
        // Transfer tokens (VULNERABLE ORDER)
        let (from_user, to_vault, from_vault, to_user) = if is_a_to_b {
            (
                ctx.accounts.user_token_a.to_account_info(),
                ctx.accounts.token_a_vault.to_account_info(),
                ctx.accounts.token_b_vault.to_account_info(),
                ctx.accounts.user_token_b.to_account_info(),
            )
        } else {
            (
                ctx.accounts.user_token_b.to_account_info(),
                ctx.accounts.token_b_vault.to_account_info(),
                ctx.accounts.token_a_vault.to_account_info(),
                ctx.accounts.user_token_a.to_account_info(),
            )
        };

        // Transfer in
        token::transfer(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: from_user,
                    to: to_vault,
                    authority: ctx.accounts.user.to_account_info(),
                },
            ),
            amount_in,
        )?;

        // Transfer out (BEFORE state update - vulnerable!)
        let seeds = &[
            b"pool".as_ref(),
            pool.token_a_mint.as_ref(),
            pool.token_b_mint.as_ref(),
            &[ctx.bumps.pool],
        ];
        let signer_seeds = &[&seeds[..]];

        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: from_vault,
                    to: to_user,
                    authority: pool.to_account_info(),
                },
                signer_seeds,
            ),
            amount_out,
        )?;

        // ⚠️ BUG #6: State update AFTER external calls
        // If there was a callback, it would see stale reserves
        if is_a_to_b {
            pool.reserve_a = new_reserve_in;
            pool.reserve_b = new_reserve_out;
        } else {
            pool.reserve_b = new_reserve_in;
            pool.reserve_a = new_reserve_out;
        }

        msg!("Swapped {} -> {}", amount_in, amount_out);
        Ok(())
    }

    /// ⚠️ BUG #7: Swap with unchecked pool account
    pub fn swap_unchecked(
        ctx: Context<SwapUnchecked>,
        amount_in: u64,
        is_a_to_b: bool,
    ) -> Result<()> {
        // ⚠️ BUG #7: Pool is UncheckedAccount - attacker can pass fake pool!
        let pool_data = ctx.accounts.pool.try_borrow_data()?;
        
        // Manually deserialize (vulnerable - no owner check!)
        let reserve_a = u64::from_le_bytes(pool_data[73..81].try_into().unwrap());
        let reserve_b = u64::from_le_bytes(pool_data[81..89].try_into().unwrap());

        let (reserve_in, reserve_out) = if is_a_to_b {
            (reserve_a, reserve_b)
        } else {
            (reserve_b, reserve_a)
        };

        let amount_out = reserve_out * amount_in / (reserve_in + amount_in);

        msg!("Unchecked swap: {} -> {} (VULNERABLE!)", amount_in, amount_out);
        
        // In a real exploit, tokens would be transferred here
        // We just log to demonstrate the vulnerability
        
        Ok(())
    }

    /// ⚠️ BUG #3: Spot price oracle (directly manipulable)
    pub fn get_price(ctx: Context<GetPrice>) -> Result<u64> {
        let pool = &ctx.accounts.pool;
        
        // VULNERABLE: Returns spot price which can be manipulated!
        // A flash loan can temporarily change reserves
        let price = if pool.reserve_a > 0 {
            pool.reserve_b * 1_000_000 / pool.reserve_a // Price with 6 decimal precision
        } else {
            0
        };

        msg!("Spot price (MANIPULABLE): {}", price);
        Ok(price)
    }
}

// ============================================================================
// ACCOUNT STRUCTURES
// ============================================================================

/// ⚠️ BUG #8: No seeds constraint - pool address not deterministic
#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + Pool::INIT_SPACE,
        // BUG: Should have seeds for deterministic address!
        // seeds = [b"pool", token_a_mint.key().as_ref(), token_b_mint.key().as_ref()],
        // bump
    )]
    pub pool: Account<'info, Pool>,

    pub token_a_mint: Account<'info, Mint>,
    pub token_b_mint: Account<'info, Mint>,

    #[account(mut)]
    pub token_a_vault: Account<'info, TokenAccount>,
    #[account(mut)]
    pub token_b_vault: Account<'info, TokenAccount>,

    #[account(mut)]
    pub lp_mint: Account<'info, Mint>,

    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct AddLiquidity<'info> {
    #[account(
        mut,
        seeds = [b"pool", pool.token_a_mint.as_ref(), pool.token_b_mint.as_ref()],
        bump,
    )]
    pub pool: Account<'info, Pool>,

    #[account(mut)]
    pub token_a_vault: Account<'info, TokenAccount>,
    #[account(mut)]
    pub token_b_vault: Account<'info, TokenAccount>,

    #[account(mut)]
    pub lp_mint: Account<'info, Mint>,

    #[account(mut)]
    pub user_token_a: Account<'info, TokenAccount>,
    #[account(mut)]
    pub user_token_b: Account<'info, TokenAccount>,
    #[account(mut)]
    pub user_lp_account: Account<'info, TokenAccount>,

    #[account(mut)]
    pub user: Signer<'info>,
    pub token_program: Program<'info, Token>,
}

/// ⚠️ BUG #4: lp_owner is AccountInfo, not Signer!
#[derive(Accounts)]
pub struct RemoveLiquidity<'info> {
    #[account(
        mut,
        seeds = [b"pool", pool.token_a_mint.as_ref(), pool.token_b_mint.as_ref()],
        bump,
    )]
    pub pool: Account<'info, Pool>,

    #[account(mut)]
    pub token_a_vault: Account<'info, TokenAccount>,
    #[account(mut)]
    pub token_b_vault: Account<'info, TokenAccount>,

    #[account(mut)]
    pub lp_mint: Account<'info, Mint>,

    #[account(mut)]
    pub user_token_a: Account<'info, TokenAccount>,
    #[account(mut)]
    pub user_token_b: Account<'info, TokenAccount>,
    #[account(mut)]
    pub user_lp_account: Account<'info, TokenAccount>,

    /// CHECK: ⚠️ VULNERABLE - This should be Signer<'info>!
    /// Anyone can pass any pubkey here without proving ownership
    #[account(mut)]
    pub lp_owner: AccountInfo<'info>,
    
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct Swap<'info> {
    #[account(
        mut,
        seeds = [b"pool", pool.token_a_mint.as_ref(), pool.token_b_mint.as_ref()],
        bump,
    )]
    pub pool: Account<'info, Pool>,

    #[account(mut)]
    pub token_a_vault: Account<'info, TokenAccount>,
    #[account(mut)]
    pub token_b_vault: Account<'info, TokenAccount>,

    #[account(mut)]
    pub user_token_a: Account<'info, TokenAccount>,
    #[account(mut)]
    pub user_token_b: Account<'info, TokenAccount>,

    #[account(mut)]
    pub user: Signer<'info>,
    pub token_program: Program<'info, Token>,
}

/// ⚠️ BUG #7: Uses UncheckedAccount for pool - no owner verification!
#[derive(Accounts)]
pub struct SwapUnchecked<'info> {
    /// CHECK: ⚠️ VULNERABLE - No owner check, attacker can pass fake pool!
    #[account(mut)]
    pub pool: UncheckedAccount<'info>,

    #[account(mut)]
    pub token_a_vault: Account<'info, TokenAccount>,
    #[account(mut)]
    pub token_b_vault: Account<'info, TokenAccount>,

    #[account(mut)]
    pub user_token_a: Account<'info, TokenAccount>,
    #[account(mut)]
    pub user_token_b: Account<'info, TokenAccount>,

    #[account(mut)]
    pub user: Signer<'info>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct GetPrice<'info> {
    pub pool: Account<'info, Pool>,
}

// ============================================================================
// STATE
// ============================================================================

#[account]
#[derive(InitSpace)]
pub struct Pool {
    pub authority: Pubkey,         // 32 bytes
    pub token_a_mint: Pubkey,      // 32 bytes
    pub token_b_mint: Pubkey,      // 32 bytes
    pub token_a_vault: Pubkey,     // 32 bytes
    pub token_b_vault: Pubkey,     // 32 bytes
    pub lp_mint: Pubkey,           // 32 bytes
    pub reserve_a: u64,            // 8 bytes (offset: 73)
    pub reserve_b: u64,            // 8 bytes
    pub total_lp_supply: u64,      // 8 bytes
    pub fee_bps: u64,              // 8 bytes
    pub last_update: i64,          // 8 bytes (for TWAP - unused in vulnerable)
    pub price_cumulative: u128,    // 16 bytes (for TWAP - unused in vulnerable)
}

// ============================================================================
// ERRORS
// ============================================================================

#[error_code]
pub enum AmmError {
    #[msg("Slippage tolerance exceeded")]
    SlippageExceeded,
    #[msg("Insufficient liquidity")]
    InsufficientLiquidity,
    #[msg("Overflow in calculation")]
    Overflow,
    #[msg("Invalid pool")]
    InvalidPool,
    #[msg("Unauthorized")]
    Unauthorized,
}

// ============================================================================
// HELPERS
// ============================================================================

/// Simple integer square root using Newton's method
fn integer_sqrt(n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    let mut x = n;
    let mut y = (x + 1) / 2;
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}
