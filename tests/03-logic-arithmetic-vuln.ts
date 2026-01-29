import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { assert } from "chai";
import { Keypair, PublicKey, SystemProgram } from "@solana/web3.js";
import { IntegerOverflowVulnerable } from "../target/types/integer_overflow_vulnerable";
import { PrecisionLossVulnerable } from "../target/types/precision_loss_vulnerable";

describe("Logic & Arithmetic - Vulnerable Programs", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  // ════════════════════════════════════════════════════════════
  // 01 - INTEGER OVERFLOW/UNDERFLOW
  // ════════════════════════════════════════════════════════════
  describe("Integer Overflow/Underflow", () => {
    const program = anchor.workspace.IntegerOverflowVulnerable as Program<IntegerOverflowVulnerable>;
    
    const staker = Keypair.generate();
    let poolPda: PublicKey;
    let userStakePda: PublicKey;

    before(async () => {
      // Fund staker
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

    it("VULNERABILITY: Wrapping add causes overflow", async () => {
      // Stake a huge amount first (simulated by manipulating or just creating scenario)
      // Since we can't mint fake tokens here efficiently without token program,
      // we rely on the u64 input to the instruction.
      
      const HUGE_AMOUNT = new anchor.BN("18446744073709551500"); // u64::MAX - 115
      
      await program.methods.stake(HUGE_AMOUNT)
        .accounts({
          pool: poolPda,
          userStake: userStakePda,
          staker: staker.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([staker])
        .rpc();

      // Now add 200 more. wrap max is ~18.44e18
      // Expected: HUGE + 200 = overflow to small number (around 84)
      const SMALL_ADD = new anchor.BN(200);

      await program.methods.stake(SMALL_ADD)
        .accounts({
          pool: poolPda,
          userStake: userStakePda,
          staker: staker.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([staker])
        .rpc();

      const poolAccount = await program.account.stakingPool.fetch(poolPda);
      
      console.log("\n  VULNERABILITY:");
      console.log("  - Staked u64::MAX - 115");
      console.log("  - Added 200");
      console.log("  - Result wrapped to:", poolAccount.totalStaked.toString());
      
      assert.isTrue(poolAccount.totalStaked.lt(new anchor.BN(100)), "Total staked should have wrapped to small number");
    });
  });

  // ════════════════════════════════════════════════════════════
  // 02 - PRECISION LOSS
  // ════════════════════════════════════════════════════════════
  describe("Precision Loss", () => {
    const program = anchor.workspace.PrecisionLossVulnerable as Program<PrecisionLossVulnerable>;
    
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

    it("Initialize Pool (10,000 assets, 1,000 shares)", async () => {
      await program.methods.initialize()
        .accounts({
          pool: poolPda,
          authority: provider.wallet.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();
    });

    it("VULNERABILITY: Withdrawing small share amount results in 0 assets", async () => {
      // 10 shares out of 1000. 1% of pool.
      // Pool has 10,000,000 assets. 1% = 100,000 assets.
      // Bug: (10 / 1000) * 10,000,000 = 0 * 10,000,000 = 0
      
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

      
      console.log("\n  VULNERABILITY:");
      console.log("  - Withdrew 10 shares (1% of 1000)");
      console.log("  - Expected assets: 100");
      console.log("  - Actual assets received:", userAccount.lastWithdrawal.toString());
      
      assert.equal(userAccount.lastWithdrawal.toNumber(), 0, "User received 0 due to precision loss");
    });
  });
});
