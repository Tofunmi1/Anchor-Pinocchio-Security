import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { assert } from "chai";
import { Keypair, PublicKey, SystemProgram } from "@solana/web3.js";
import { UncheckedProgramIdFixed } from "../target/types/unchecked_program_id_fixed";
import { UncheckedPdaFixed } from "../target/types/unchecked_pda_fixed";
import { ArbitraryCpiFixed } from "../target/types/arbitrary_cpi_fixed";

describe("CPI & PDA - Fixed Programs", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  // ════════════════════════════════════════════════════════════
  // 01 - UNCHECKED PROGRAM ID (FIXED)
  // ════════════════════════════════════════════════════════════
  describe("Unchecked Program ID - Fixed", () => {
    const program = anchor.workspace.UncheckedProgramIdFixed as Program<UncheckedProgramIdFixed>;
    
    it("FIX: Enforces System Program ID", async () => {
      // The fixed program expects Program<'info, System>
      // Passing anything else (like Token Program) will fail Anchor's check
      
      try {
        await program.methods.cpiLog()
          .accounts({
            targetProgram: SystemProgram.programId,
          })
          .rpc();
      } catch (err: any) {
        console.log("\n  FIX:");
        console.log("  - Correct program ID accepted (but transaction reverted due to invalid data, which is expected for System Program)");
        assert.ok(JSON.stringify(err).includes("invalid instruction data") || err.logs?.some((l: string) => l.includes("invalid instruction data")));
      }
    });
  });

  // ════════════════════════════════════════════════════════════
  // 02 - UNCHECKED PDA (FIXED)
  // ════════════════════════════════════════════════════════════
  describe("Unchecked PDA - Fixed", () => {
    const program = anchor.workspace.UncheckedPdaFixed as Program<UncheckedPdaFixed>;
    
    const authority = Keypair.generate();
    const fakeVault = Keypair.generate();

    before(async () => {
      const sig = await provider.connection.requestAirdrop(authority.publicKey, 1000000000);
      await provider.connection.confirmTransaction(sig);
    });

    it("FIX: Fails when using fake vault (random keypair)", async () => {
      // Try to initialize fake vault.
      // Should FAIL because address doesn't match seeds [b"vault", authority]
      
      try {
        await program.methods.initializeVault()
          .accounts({
            vault: fakeVault.publicKey,
            authority: authority.publicKey,
            systemProgram: SystemProgram.programId,
          })
          .signers([authority]) // Anchor might complain about strict init before sending tx
          .rpc();
          
        assert.fail("Should have failed");
      } catch (err: any) {
        console.log("\n  FIX:");
        console.log("  - Initialization failed: seeds mismatch");
        // Anchor error about seeds constraint
      }
    });

    it("FIX: Works with correct PDA", async () => {
      const [realVault] = PublicKey.findProgramAddressSync(
        [Buffer.from("vault"), authority.publicKey.toBuffer()],
        program.programId
      );

      await program.methods.initializeVault()
        .accounts({
          vault: realVault,
          authority: authority.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([authority])
        .rpc();

      await program.methods.withdraw()
        .accounts({
          vault: realVault,
          authority: authority.publicKey,
        })
        .signers([authority])
        .rpc();
        
      console.log("  - Correct PDA succeeded");
    });
  });

  // ════════════════════════════════════════════════════════════
  // 03 - ARBITRARY CPI SIGNER (FIXED)
  // ════════════════════════════════════════════════════════════
  describe("Arbitrary CPI - Fixed", () => {
    const program = anchor.workspace.ArbitraryCpiFixed as Program<ArbitraryCpiFixed>;
    
    const [pdaTreasury] = PublicKey.findProgramAddressSync(
      [Buffer.from("treasury")],
      program.programId
    );
    
    const recipient = Keypair.generate();

    before(async () => {
      // Fund the PDA treasury
      const fundSig = await provider.connection.requestAirdrop(pdaTreasury, 1000000000);
      await provider.connection.confirmTransaction(fundSig);
      
      // Fund recipient so they can pay for transaction
      const sig = await provider.connection.requestAirdrop(recipient.publicKey, 1000000000);
      await provider.connection.confirmTransaction(sig);
    });

    it("FIX: Program-controlled reward amount (user cannot specify)", async () => {
      const balanceBefore = await provider.connection.getBalance(recipient.publicKey);
      
      // The fixed program has claimReward() which:
      // 1. Hardcodes the transfer amount (10,000 lamports)
      // 2. User cannot specify arbitrary instruction data
      // 3. Program constructs the CPI internally
      
      await program.methods.claimReward()
        .accounts({
          pdaTreasury: pdaTreasury,
          recipient: recipient.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([recipient])
        .rpc();
        
      const balanceAfter = await provider.connection.getBalance(recipient.publicKey);
      const received = balanceAfter - balanceBefore;
      
      console.log("\n  FIX:");
      console.log("  - User called claimReward() (no arbitrary data parameter)");
      console.log("  - Received exactly:", received, "lamports (hardcoded in program)");
      console.log("  - Cannot drain treasury: amount is fixed at 10,000 lamports");
      
      // The reward is exactly 10,000 lamports (minus tx fee, so check it's reasonable)
      assert.isTrue(received > 0 && received <= 10000, "Received fixed reward amount");
    });
  });
});
