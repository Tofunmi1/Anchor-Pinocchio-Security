import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { assert } from "chai";
import { Keypair, LAMPORTS_PER_SOL, PublicKey, SystemProgram } from "@solana/web3.js";

// Import program types - local target folder
import { MissingSignerVulnerable } from "../target/types/missing_signer_vulnerable";
import { MissingOwnerVulnerable } from "../target/types/missing_owner_vulnerable";
import { PdaSubstitutionVulnerable } from "../target/types/pda_substitution_vulnerable";

/**
 * Access Control Vulnerabilities - Understanding the Bugs
 * 
 * These tests demonstrate the vulnerability patterns.
 * NOTE: Some exploits can't be fully demonstrated because
 * the Anchor client adds client-side protections.
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
    let aliceVault: PublicKey;
    const DEPOSIT = 5 * LAMPORTS_PER_SOL;

    before(async () => {
      const sig1 = await provider.connection.requestAirdrop(alice.publicKey, 10 * LAMPORTS_PER_SOL);
      await provider.connection.confirmTransaction(sig1);

      [aliceVault] = PublicKey.findProgramAddressSync(
        [Buffer.from("vault"), alice.publicKey.toBuffer()],
        program.programId
      );
    });

    it("Setup: Alice creates vault and deposits 5 SOL", async () => {
      await program.methods.initialize()
        .accounts({
          vault: aliceVault,
          authority: alice.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([alice])
        .rpc();

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

    it("VULNERABILITY: authority is AccountInfo, not Signer", async () => {
      /**
       * THE VULNERABILITY EXPLAINED:
       * 
       * In Withdraw struct (line 92-102 of vulnerable code):
       * 
       *   pub authority: AccountInfo<'info>   // <-- BUG!
       * 
       * Should be:
       * 
       *   pub authority: Signer<'info>        // <-- FIXED
       * 
       * The program only checks:
       *   require_keys_eq!(vault.authority, ctx.accounts.authority.key())
       * 
       * This verifies the KEY matches, but NOT that they SIGNED.
       * 
       * In a real exploit (using raw transactions, not Anchor client):
       * 1. Attacker constructs transaction with alice.pubkey as authority
       * 2. Attacker signs with their own keypair (to pay fees)
       * 3. Program sees authority.key() == vault.authority ✓
       * 4. Program never checks authority.is_signer ✗
       * 5. Funds are transferred to alice.pubkey (controlled by attacker in instruction)
       * 
       * The Anchor client prevents this client-side, but a malicious
       * client or raw transaction builder can exploit this.
       */

      console.log("\n  VULNERABILITY:");
      console.log("  - authority is AccountInfo<'info>, not Signer<'info>");
      console.log("  - Program checks: require_keys_eq!(vault.authority, authority.key())");
      console.log("  - But NEVER checks: authority.is_signer");
      console.log("  - A raw transaction can exploit this\n");

      // Verify vault has funds (exploit would drain these)
      const vault = await program.account.vault.fetch(aliceVault);
      assert.equal(vault.balance.toNumber(), DEPOSIT);
    });
  });

  // ════════════════════════════════════════════════════════════
  // 02 - MISSING OWNER CHECK
  // ════════════════════════════════════════════════════════════
  describe("Missing Owner Check", () => {
    const program = anchor.workspace.MissingOwnerVulnerable as Program<MissingOwnerVulnerable>;

    it("VULNERABILITY: UncheckedAccount accepts any account", async () => {
      /**
       * THE VULNERABILITY:
       * Using UncheckedAccount without verifying account.owner == program_id
       * 
       * Attack scenario:
       * 1. Attacker creates account with System Program as owner
       * 2. Writes crafted data: { owner: attacker_pubkey, balance: X }
       * 3. Passes this fake "vault" to withdraw function
       * 4. Program reads crafted data, thinks attacker is authorized
       */

      console.log("\n  VULNERABILITY:");
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

    it("VULNERABILITY: No seeds verification allows wrong PDA", async () => {
      /**
       * THE VULNERABILITY:
       * Account<'info, UserVault> WITHOUT seeds constraint
       * 
       * - Program verifies owner (program owns it) ✓
       * - Program verifies discriminator (it's a UserVault) ✓
       * - But doesn't verify WHICH user's vault ✗
       * 
       * If the user field can be set or matched by attacker,
       * they can substitute a different vault.
       */

      console.log("\n  VULNERABILITY:");
      console.log("  - Account type verifies owner and discriminator");
      console.log("  - But no seeds constraint to verify PDA derivation");
      console.log("  - Attacker could substitute valid but wrong vault\n");
    });
  });
});
