import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { assert } from "chai";
import { Keypair, PublicKey, SystemProgram } from "@solana/web3.js";
import { IntegerOverflowFixed } from "../target/types/integer_overflow_fixed";
import { PrecisionLossFixed } from "../target/types/precision_loss_fixed";

describe("Logic & Arithmetic - Fixed Programs", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  // ════════════════════════════════════════════════════════════
  // 01 - INTEGER OVERFLOW/UNDERFLOW (FIXED)
  // ════════════════════════════════════════════════════════════
  describe("Integer Overflow - Fixed", () => {
    const program = anchor.workspace.IntegerOverflowFixed as Program<IntegerOverflowFixed>;
    
    const staker = Keypair.generate();
    let poolPda: PublicKey;
    let userStakePda: PublicKey;

    before(async () => {
      const sig = await provider.connection.requestAirdrop(staker.publicKey, 1000000000);
      await provider.connection.confirmTransaction(sig);

      [poolPda] = PublicKey.findProgramAddressSync(
        [Buffer.from("pool")],
        program.programId
      );

      [userStakePda] = PublicKey.findProgramAddressSync(
        [Buffer.from("user_stake"), staker.publicKey.toBuffer()],
        program.programId
      );
    });

    it("Initialize Pool", async () => {
      await program.methods.initialize()
        .accounts({
          pool: poolPda,
          authority: provider.wallet.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();
    });

    it("FIX: Checked arithmetic prevents overflow", async () => {
      const HUGE_AMOUNT = new anchor.BN("18446744073709551500");
      
      // First stake works fine
      await program.methods.stake(HUGE_AMOUNT)
        .accounts({
          pool: poolPda,
          userStake: userStakePda,
          staker: staker.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([staker])
        .rpc();

      // Second stake causes overflow, should fail
      const SMALL_ADD = new anchor.BN(200);

      try {
        await program.methods.stake(SMALL_ADD)
          .accounts({
            pool: poolPda,
            userStake: userStakePda,
            staker: staker.publicKey,
            systemProgram: SystemProgram.programId,
          })
          .signers([staker])
          .rpc();
        
        assert.fail("Should have failed with overflow");
      } catch (err: any) {
        console.log("\n  FIX:");
        console.log("  - overflow detected by checked_add");
        assert.ok(err.message.includes("Overflow"), "Error should be about overflow");
      }
    });
  });

  // ════════════════════════════════════════════════════════════
  // 02 - PRECISION LOSS (FIXED)
  // ════════════════════════════════════════════════════════════
  describe("Precision Loss - Fixed", () => {
    const program = anchor.workspace.PrecisionLossFixed as Program<PrecisionLossFixed>;
    
    const user = Keypair.generate();
    let poolPda: PublicKey;
    let userPda: PublicKey;

    before(async () => {
      const sig = await provider.connection.requestAirdrop(user.publicKey, 1000000000);
      await provider.connection.confirmTransaction(sig);

      [poolPda] = PublicKey.findProgramAddressSync(
        [Buffer.from("pool")],
        program.programId
      );

      [userPda] = PublicKey.findProgramAddressSync(
        [Buffer.from("user"), user.publicKey.toBuffer()],
        program.programId
      );
    });

    it("Initialize Pool", async () => {
      await program.methods.initialize()
        .accounts({
          pool: poolPda,
          authority: provider.wallet.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();
    });

    it("FIX: Correct calculation using multiplication first", async () => {
      // Same scenario: 10 shares (1%)
      // Math: (10 * 10,000,000) / 1,000 = 100,000,000 / 1,000 = 100,000
      
      const sharesToWithdraw = new anchor.BN(10);
      
      await program.methods.withdrawShare(sharesToWithdraw)
        .accounts({
          pool: poolPda,
          user: userPda,
          userAuthority: user.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([user])
        .rpc();

      const userAccount = await program.account.user.fetch(userPda);
      
      console.log("\n  FIX:");
      console.log("  - Withdrew 10 shares");
      console.log("  - Actual assets received:", userAccount.lastWithdrawal.toString());
      
      assert.equal(userAccount.lastWithdrawal.toNumber(), 100000, "Calculated correctly");
    });
  });
});
