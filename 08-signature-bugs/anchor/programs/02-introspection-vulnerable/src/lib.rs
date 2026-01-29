use anchor_lang::prelude::*;
use anchor_lang::solana_program::pubkey;

declare_id!("9yTg5P8YN5D6wJ5C3g5ukwBXaKBq8Q3GzfYs5Q3pZaC1");

/// Ed25519 native program ID
const ED25519_PROGRAM_ID: Pubkey = pubkey!("Ed25519SigVerify111111111111111111111111111");

/// # Ed25519 Verification Bypass Vulnerability
/// 
/// This program demonstrates a vulnerability in Ed25519 signature verification
/// when using Solana's native Ed25519 program via instruction introspection.
/// 
/// ## Background: Off-Chain Signatures
/// 
/// Sometimes programs need to verify signatures created off-chain (not as part
/// of the transaction signing). For example:
/// - Gasless transactions where a relayer pays fees
/// - Cross-chain message verification
/// - Order signing for DEXs
/// 
/// Solana provides the Ed25519 native program (Ed25519Program) that can verify
/// Ed25519 signatures. Programs can check if a signature was verified by
/// inspecting the instructions in the same transaction.
/// 
/// ## The Vulnerability
/// 
/// This program checks if an Ed25519 verify instruction EXISTS in the transaction,
/// but fails to verify:
/// 1. That the signature was for the expected message/pubkey
/// 2. That the verification actually SUCCEEDED
/// 
/// An attacker can include a valid Ed25519 verify instruction for ANY signature,
/// not necessarily one that authorizes the action they're taking.

#[program]
pub mod introspection_vulnerable {
    use super::*;

    /// Initializes a claimable reward pool.
    pub fn initialize(ctx: Context<Initialize>, reward_amount: u64) -> Result<()> {
        let reward = &mut ctx.accounts.reward;
        reward.authority = ctx.accounts.authority.key();
        reward.amount = reward_amount;
        reward.claimed = false;
        
        emit!(RewardInitialized {
            reward: reward.key(),
            authority: reward.authority,
            amount: reward_amount,
        });
        
        Ok(())
    }

    /// Claims a reward using Ed25519 signature verification.
    /// 
    /// ## Vulnerability: Insufficient Introspection Validation
    /// 
    /// This function only checks that an Ed25519 verify instruction exists
    /// in the transaction, but doesn't verify:
    /// - The signature corresponds to the correct public key
    /// - The signature is over the expected message (e.g., claim authorization)
    /// - The verification instruction actually succeeded
    /// 
    /// An attacker can:
    /// 1. Create a valid signature for any arbitrary message with any key
    /// 2. Include Ed25519 verify instruction in the same transaction
    /// 3. The check passes even though the signature doesn't authorize the claim
    pub fn claim_reward(ctx: Context<ClaimReward>) -> Result<()> {
        let reward = &mut ctx.accounts.reward;
        let instruction_sysvar = &ctx.accounts.instruction_sysvar;
        
        // Load all instructions in the current transaction
        let current_index = anchor_lang::solana_program::sysvar::instructions::load_current_index_checked(
            instruction_sysvar
        )?;
        
        // VULNERABLE: Only checks if Ed25519 program was invoked
        // Does NOT verify the signature content or success
        let mut found_ed25519 = false;
        
        for i in 0..current_index {
            let ix = anchor_lang::solana_program::sysvar::instructions::load_instruction_at_checked(
                i as usize,
                instruction_sysvar
            )?;
            
            // Just checking if Ed25519 program ID exists - not validating content!
            if ix.program_id == ED25519_PROGRAM_ID {
                found_ed25519 = true;
                break;
            }
        }
        
        require!(found_ed25519, IntrospectionError::MissingSignature);
        require!(!reward.claimed, IntrospectionError::AlreadyClaimed);
        
        // VULNERABILITY: We never verified WHAT was signed or by WHOM!
        // Any Ed25519 signature passes this check.
        
        reward.claimed = true;
        
        emit!(RewardClaimed {
            reward: reward.key(),
            claimer: ctx.accounts.claimer.key(),
            amount: reward.amount,
        });
        
        msg!("Reward claimed: {} lamports", reward.amount);
        
        Ok(())
    }
}

// ============================================================================
// Account Contexts
// ============================================================================

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = authority, space = 8 + Reward::INIT_SPACE)]
    pub reward: Account<'info, Reward>,
    
    #[account(mut)]
    pub authority: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct ClaimReward<'info> {
    #[account(mut)]
    pub reward: Account<'info, Reward>,
    
    #[account(mut)]
    pub claimer: Signer<'info>,
    
    /// CHECK: Instruction sysvar for introspection
    #[account(address = anchor_lang::solana_program::sysvar::instructions::ID)]
    pub instruction_sysvar: AccountInfo<'info>,
}

// ============================================================================
// Account Structures
// ============================================================================

#[account]
#[derive(InitSpace)]
pub struct Reward {
    /// The authority whose signature should be required for claiming.
    pub authority: Pubkey,
    
    /// Amount of reward in lamports.
    pub amount: u64,
    
    /// Whether the reward has been claimed.
    pub claimed: bool,
}

// ============================================================================
// Events
// ============================================================================

#[event]
pub struct RewardInitialized {
    pub reward: Pubkey,
    pub authority: Pubkey,
    pub amount: u64,
}

#[event]
pub struct RewardClaimed {
    pub reward: Pubkey,
    pub claimer: Pubkey,
    pub amount: u64,
}

// ============================================================================
// Errors
// ============================================================================

#[error_code]
pub enum IntrospectionError {
    #[msg("Missing Ed25519 signature verification instruction.")]
    MissingSignature,
    #[msg("Reward has already been claimed.")]
    AlreadyClaimed,
}
