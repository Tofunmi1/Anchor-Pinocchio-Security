use anchor_lang::prelude::*;

declare_id!("J3Ef3qxyeSK24Sk9deRbpRKfvbQ5xE1e4byYi6ZBuXoT");

/// FIXED: Account Resurrection Prevention
/// 
/// This program uses Anchor's `close` constraint which:
/// 1. Zeros all account data
/// 2. Sets discriminator to closed state
/// 3. Drains lamports to recipient
/// 
/// Even if lamports are refunded, the zeroed data prevents resurrection.

#[program]
pub mod account_resurrection_fixed {
    use super::*;

    /// Create an escrow for a user
    pub fn create_escrow(ctx: Context<CreateEscrow>, amount: u64) -> Result<()> {
        let escrow = &mut ctx.accounts.escrow;
        escrow.owner = ctx.accounts.owner.key();
        escrow.amount = amount;
        escrow.claimed = false;
        
        // Transfer funds to escrow
        let ix = anchor_lang::solana_program::system_instruction::transfer(
            &ctx.accounts.owner.key(),
            &escrow.key(),
            amount,
        );
        anchor_lang::solana_program::program::invoke(
            &ix,
            &[
                ctx.accounts.owner.to_account_info(),
                escrow.to_account_info(),
            ],
        )?;
        
        msg!("Escrow created: {} lamports", amount);
        Ok(())
    }

    /// Claim escrow - marks as claimed and transfers funds
    pub fn claim(ctx: Context<Claim>) -> Result<()> {
        let escrow = &mut ctx.accounts.escrow;
        require!(!escrow.claimed, EscrowError::AlreadyClaimed);
        
        escrow.claimed = true;
        
        let escrow_lamports = ctx.accounts.escrow.to_account_info().lamports();
        let rent = Rent::get()?;
        let min_rent = rent.minimum_balance(Escrow::INIT_SPACE + 8);
        let claimable = escrow_lamports.saturating_sub(min_rent);
        
        **ctx.accounts.escrow.to_account_info().try_borrow_mut_lamports()? -= claimable;
        **ctx.accounts.owner.to_account_info().try_borrow_mut_lamports()? += claimable;
        
        msg!("Claimed {} lamports", claimable);
        Ok(())
    }

    /// Close escrow - FIX: uses Anchor's close constraint
    /// 
    /// The `close = owner` constraint:
    /// 1. Zeros all data (including discriminator)
    /// 2. Transfers all lamports to owner
    /// 
    /// Even if lamports are refunded:
    /// - Data is zeroed (claimed=false doesn't exist)
    /// - Discriminator is zeroed (won't deserialize as Escrow)
    pub fn close_escrow(_ctx: Context<CloseEscrow>) -> Result<()> {
        msg!("Escrow closed safely (data zeroed)");
        Ok(())
    }
}

#[derive(Accounts)]
pub struct CreateEscrow<'info> {
    #[account(
        init,
        payer = owner,
        space = 8 + Escrow::INIT_SPACE,
        seeds = [b"escrow", owner.key().as_ref()],
        bump
    )]
    pub escrow: Account<'info, Escrow>,
    
    #[account(mut)]
    pub owner: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Claim<'info> {
    #[account(
        mut,
        has_one = owner,
    )]
    pub escrow: Account<'info, Escrow>,
    
    #[account(mut)]
    pub owner: Signer<'info>,
}

#[derive(Accounts)]
pub struct CloseEscrow<'info> {
    #[account(
        mut,
        has_one = owner,
        close = owner  // <-- FIX: Anchor's close constraint zeros data
    )]
    pub escrow: Account<'info, Escrow>,
    
    #[account(mut)]
    pub owner: Signer<'info>,
}

#[account]
#[derive(InitSpace)]
pub struct Escrow {
    pub owner: Pubkey,   // 32 bytes
    pub amount: u64,     // 8 bytes
    pub claimed: bool,   // 1 byte
}

#[error_code]
pub enum EscrowError {
    #[msg("Escrow has already been claimed")]
    AlreadyClaimed,
}
