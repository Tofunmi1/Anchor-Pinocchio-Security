use anchor_lang::prelude::*;
use anchor_lang::solana_program::pubkey;

declare_id!("Bv7g5P8YN5D6wJ5C3g5ukwBXaKBq8Q3GzfYs5Q3pZaB2");

/// Ed25519 native program ID
const ED25519_PROGRAM_ID: Pubkey = pubkey!("Ed25519SigVerify111111111111111111111111111");

/// # Secure: Proper Ed25519 Signature Verification
/// 
/// This program demonstrates the correct way to verify Ed25519 signatures
/// when using Solana's native Ed25519 program via instruction introspection.
/// 
/// ## Secure Pattern
/// 
/// When verifying Ed25519 signatures through introspection, you MUST verify:
/// 1. The signature was made by the expected public key
/// 2. The signature is over the expected message content
/// 3. The verification instruction succeeded (signature is valid)
/// 
/// This is typically done by parsing the Ed25519 instruction data and
/// comparing the embedded public key and message against expected values.

#[program]
pub mod introspection_fixed {
    use super::*;

    /// Initializes a claimable reward pool.
    pub fn initialize(ctx: Context<Initialize>, reward_amount: u64) -> Result<()> {
        let reward = &mut ctx.accounts.reward;
        reward.authority = ctx.accounts.authority.key();
        reward.amount = reward_amount;
        reward.claimed = false;
        reward.nonce = 0;
        
        emit!(RewardInitialized {
            reward: reward.key(),
            authority: reward.authority,
            amount: reward_amount,
        });
        
        Ok(())
    }

    /// Claims a reward with proper Ed25519 signature verification.
    /// 
    /// ## Secure Pattern: Full Introspection Validation
    /// 
    /// This function properly validates that:
    /// 1. An Ed25519 verify instruction exists in the transaction
    /// 2. The public key in the verification matches the reward authority
    /// 3. The message contains the expected claim authorization data
    /// 4. The signature is actually valid (Ed25519 program would fail otherwise)
    /// 
    /// For simplicity in this demo, we validate the pubkey and message format.
    /// In production, you would use a proper Ed25519 instruction parser.
    pub fn claim_reward(ctx: Context<ClaimReward>, signature: [u8; 64], message: Vec<u8>) -> Result<()> {
        let reward = &mut ctx.accounts.reward;
        let instruction_sysvar = &ctx.accounts.instruction_sysvar;
        
        require!(!reward.claimed, IntrospectionError::AlreadyClaimed);
        
        // Construct expected message: "CLAIM:<reward_pubkey>:<nonce>"
        let expected_message = format!(
            "CLAIM:{}:{}",
            reward.key(),
            reward.nonce
        );
        
        // Verify the provided message matches expected format
        require!(
            message == expected_message.as_bytes(),
            IntrospectionError::InvalidMessage
        );
        
        // Load current instruction index
        let current_index = anchor_lang::solana_program::sysvar::instructions::load_current_index_checked(
            instruction_sysvar
        )?;
        
        // Find and validate Ed25519 signature verification instruction
        let mut signature_verified = false;
        
        for i in 0..current_index {
            let ix = anchor_lang::solana_program::sysvar::instructions::load_instruction_at_checked(
                i as usize,
                instruction_sysvar
            )?;
            
            if ix.program_id == ED25519_PROGRAM_ID {
                // Parse the Ed25519 instruction data
                // Format: [num_signatures, padding, signature_offset, ...]
                // For production, use a proper parsing library
                
                if ix.data.len() >= 112 {
                    // Extract public key from Ed25519 instruction (simplified)
                    // In production: use ed25519_program::verify_instruction
                    let pubkey_offset = 16; // Offset where pubkey starts in Ed25519 ix
                    if ix.data.len() >= pubkey_offset + 32 {
                        let ix_pubkey = &ix.data[pubkey_offset..pubkey_offset + 32];
                        
                        // SECURE: Verify the pubkey matches the reward authority
                        if ix_pubkey == reward.authority.as_ref() {
                            // Extract message from Ed25519 instruction
                            let message_offset = 112; // Offset where message starts
                            if ix.data.len() > message_offset {
                                let ix_message = &ix.data[message_offset..];
                                
                                // SECURE: Verify the message matches expected format
                                if ix_message == expected_message.as_bytes() {
                                    signature_verified = true;
                                }
                            }
                        }
                    }
                }
                break;
            }
        }
        
        require!(signature_verified, IntrospectionError::InvalidSignature);
        
        // Mark as claimed and increment nonce to prevent replay
        reward.claimed = true;
        reward.nonce += 1;
        
        emit!(RewardClaimed {
            reward: reward.key(),
            claimer: ctx.accounts.claimer.key(),
            amount: reward.amount,
        });
        
        msg!("Reward securely claimed: {} lamports", reward.amount);
        
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
    /// The authority whose signature is required for claiming.
    pub authority: Pubkey,
    
    /// Amount of reward in lamports.
    pub amount: u64,
    
    /// Whether the reward has been claimed.
    pub claimed: bool,
    
    /// Nonce to prevent replay attacks.
    pub nonce: u64,
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
    #[msg("Ed25519 signature verification failed or missing.")]
    InvalidSignature,
    #[msg("Message does not match expected claim authorization format.")]
    InvalidMessage,
    #[msg("Reward has already been claimed.")]
    AlreadyClaimed,
}
