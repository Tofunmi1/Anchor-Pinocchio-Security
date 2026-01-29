use anchor_lang::prelude::*;

declare_id!("686qj3aUjybLfyE3dHKzksYPj6xeqY85cfJtQxvqBTSc");

/// # Range Check Vulnerability
///
/// This program accepts any u8 value for 'level' and calculates health without
/// validating the input is within acceptable bounds. Attackers can exploit this
/// to create characters with impossible stats.

#[program]
pub mod range_check_vulnerable {
    use super::*;

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
    /// ## Vulnerability: Missing Input Validation
    /// 
    /// The program assumes levels should be 1-100, but accepts any u8 (0-255).
    /// Health is calculated as `level * 100`, so:
    /// - Level 100 → Health 10,000 (expected max)
    /// - Level 255 → Health 25,500 (2.5x intended max)
    /// 
    /// ## Exploit Scenario:
    /// 1. Game expects max level 100 with max health 10,000.
    /// 2. Attacker calls `set_level(255)`.
    /// 3. Character gets health = 25,500.
    /// 4. Attacker has 2.5x more health than any legitimate player.
    pub fn set_level(ctx: Context<SetLevel>, level: u8) -> Result<()> {
        let character = &mut ctx.accounts.character;
        
        // Vulnerability: No bounds check on level
        character.level = level;
        character.health = (level as u64) * 100;
        
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
