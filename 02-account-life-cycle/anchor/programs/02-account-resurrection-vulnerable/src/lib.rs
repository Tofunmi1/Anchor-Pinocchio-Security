use anchor_lang::prelude::*;

declare_id!("B3Eq5DhSv3WHetnJdgJbMQbtKoxSLJxREnYeXLdJiU7J");

/// VULNERABLE: Account Resurrection
/// 
/// This program closes accounts by draining lamports but doesn't
/// zero the data. If lamports are refunded in same transaction,
/// the account "resurrects" with old data intact.

#[program]
pub mod account_resurrection_vulnerable {
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
        
        // Transfer escrow funds to owner
        let escrow_lamports = ctx.accounts.escrow.to_account_info().lamports();
        let rent = Rent::get()?;
        let min_rent = rent.minimum_balance(Escrow::INIT_SPACE + 8);
        let claimable = escrow_lamports.saturating_sub(min_rent);
        
        **ctx.accounts.escrow.to_account_info().try_borrow_mut_lamports()? -= claimable;
        **ctx.accounts.owner.to_account_info().try_borrow_mut_lamports()? += claimable;
        
        msg!("Claimed {} lamports", claimable);
        Ok(())
    }

    /// Close escrow - VULNERABLE: doesn't zero data!
    /// 
    /// BUG: Only drains lamports, doesn't zero account data
    /// If lamports are refunded before tx ends, data persists
    pub fn close_escrow(ctx: Context<CloseEscrow>) -> Result<()> {
        let escrow_info = ctx.accounts.escrow.to_account_info();
        let owner_info = ctx.accounts.owner.to_account_info();
        
        // BUG: Only transfers lamports, doesn't zero data!
        let escrow_lamports = escrow_info.lamports();
        **escrow_info.try_borrow_mut_lamports()? = 0;
        **owner_info.try_borrow_mut_lamports()? += escrow_lamports;
        
        // BUG: Data not zeroed! claimed=false persists
        // If someone refunds lamports in same tx, account resurrects
        
        msg!("Escrow closed (VULNERABLE: data not zeroed)");
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
