use anchor_lang::prelude::*;

declare_id!("EfDXMep5sqCeRz2pm1q6ZBjKJjKfM3TVj1xppZALnVzY");

/// # Secure: Input Validation with Range Checks
///
/// This program validates that input values fall within acceptable bounds
/// before processing, preventing exploitation of edge cases.

#[program]
pub mod range_check_fixed {
    use super::*;

    /// Game constants
    const MAX_LEVEL: u8 = 100;
    const HEALTH_PER_LEVEL: u64 = 100;

    /// Initializes a new character for the signer.
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        emit!(CharacterCreated {
            character: ctx.accounts.character.key(),
            owner: ctx.accounts.signer.key(),
        });
        
        Ok(())
    }

    /// Sets the character's level and calculates health.
    /// 
    /// ## Secure Pattern: Input Bounds Validation
    /// 
    /// Before processing, the program validates that the level is within
    /// the acceptable range (1-100). This prevents:
    /// - Integer overflow in health calculation
    /// - Game balance exploitation via impossible stats
    /// - Unintended behavior from edge case inputs
    pub fn set_level(ctx: Context<SetLevel>, level: u8) -> Result<()> {
        let character = &mut ctx.accounts.character;
        
        // Secure: Validate input bounds
        require!(level >= 1 && level <= MAX_LEVEL, GameError::InvalidLevel);
        
        character.level = level;
        character.health = (level as u64) * HEALTH_PER_LEVEL;
        
        emit!(LevelSet {
            character: character.key(),
            level: character.level,
            health: character.health,
        });
        
        msg!("Character updated: Level {}, Health {}", character.level, character.health);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init, 
        payer = signer, 
        space = 8 + Character::INIT_SPACE, 
        seeds = [b"char", signer.key().as_ref()], 
        bump
    )]
    pub character: Account<'info, Character>,
    #[account(mut)]
    pub signer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct SetLevel<'info> {
    #[account(mut, seeds = [b"char", signer.key().as_ref()], bump)]
    pub character: Account<'info, Character>,
    pub signer: Signer<'info>,
}

#[account]
#[derive(InitSpace)]
pub struct Character {
    pub level: u8,
    pub health: u64,
}

#[event]
pub struct CharacterCreated {
    pub character: Pubkey,
    pub owner: Pubkey,
}

#[event]
pub struct LevelSet {
    pub character: Pubkey,
    pub level: u8,
    pub health: u64,
}

#[error_code]
pub enum GameError {
    #[msg("Level must be between 1 and 100.")]
    InvalidLevel,
}
