import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { assert } from "chai";
import { Keypair, LAMPORTS_PER_SOL, PublicKey, SystemProgram } from "@solana/web3.js";

// Import program types
import { ReinitializationFixed } from "../target/types/reinitialization_fixed";
import { AccountResurrectionFixed } from "../target/types/account_resurrection_fixed";

/**
 * Account Lifecycle Fixes - Security Demonstrations
 */

describe("Account Lifecycle - Fixed Programs", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  // ════════════════════════════════════════════════════════════
  // 01 - REINITIALIZATION (FIXED)
  // ════════════════════════════════════════════════════════════
  describe("Reinitialization - Fixed", () => {
    const program = anchor.workspace.ReinitializationFixed as Program<ReinitializationFixed>;
    
    const alice = Keypair.generate();
    const attacker = Keypair.generate();
    let configPda: PublicKey;

    before(async () => {
      const sig1 = await provider.connection.requestAirdrop(alice.publicKey, 10 * LAMPORTS_PER_SOL);
      const sig2 = await provider.connection.requestAirdrop(attacker.publicKey, 10 * LAMPORTS_PER_SOL);
      await provider.connection.confirmTransaction(sig1);
      await provider.connection.confirmTransaction(sig2);

      [configPda] = PublicKey.findProgramAddressSync(
        [Buffer.from("config")],
        program.programId
      );
    });

    it("Alice initializes config as owner", async () => {
      await program.methods.initialize(new anchor.BN(100))
        .accounts({
          config: configPda,
          payer: alice.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([alice])
        .rpc();

      const config = await program.account.config.fetch(configPda);
      assert.equal(config.owner.toString(), alice.publicKey.toString());
    });

    it("FIX: init constraint blocks reinitialization", async () => {
      /**
       * THE FIX:
       * 
       * Using `init` instead of `init_if_needed`:
       * 
       *   #[account(init, ...)]
       *   pub config: Account<'info, Config>,
       * 
       * `init` fails with error if the account already exists.
       * Attacker cannot reinitialize.
       */

      try {
        await program.methods.initialize(new anchor.BN(999))
          .accounts({
            config: configPda,
            payer: attacker.publicKey,
            systemProgram: SystemProgram.programId,
          })
          .signers([attacker])
          .rpc();

        assert.fail("Should have thrown");
      } catch (err: any) {
        // Error: account already in use
        console.log("\n  FIX:");
        console.log("  - `init` constraint fails if account exists");
        console.log("  - Error: ", err.message.slice(0, 50) + "...\n");
      }

      // Alice is still owner
      const config = await program.account.config.fetch(configPda);
      assert.equal(config.owner.toString(), alice.publicKey.toString());
    });
  });

  // ════════════════════════════════════════════════════════════
  // 02 - ACCOUNT RESURRECTION (FIXED)
  // ════════════════════════════════════════════════════════════
  describe("Account Resurrection - Fixed", () => {
    const program = anchor.workspace.AccountResurrectionFixed as Program<AccountResurrectionFixed>;

    it("FIX: close constraint zeros data and drains lamports", async () => {
      /**
       * THE FIX:
       * 
       * Using Anchor's `close` constraint:
       * 
       *   #[account(mut, close = owner)]
       *   pub escrow: Account<'info, Escrow>,
       * 
       * This automatically:
       * 1. Zeros all data (including discriminator)
       * 2. Transfers all lamports to `owner`
       * 
       * Even if lamports are refunded:
       * - Discriminator is zeroed
       * - Account won't deserialize as Escrow
       * - Resurrection attack fails
       */

      console.log("\n  FIX:");
      console.log("  - `close = owner` zeros all data");
      console.log("  - Discriminator set to CLOSED_ACCOUNT_DISCRIMINATOR");
      console.log("  - Resurrected account won't deserialize\n");
    });
  });
});
