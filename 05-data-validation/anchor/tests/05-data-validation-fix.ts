import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { assert } from "chai";
import { Keypair, PublicKey, SystemProgram } from "@solana/web3.js";
import { TypeConfusionFixed } from "../target/types/type_confusion_fixed";
import { RangeCheckFixed } from "../target/types/range_check_fixed";
import { DuplicateAccountFixed } from "../target/types/duplicate_account_fixed";

describe("Data Validation Security Patches", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  describe("Type Confusion Patch", () => {
    const program = anchor.workspace.TypeConfusionFixed as Program<TypeConfusionFixed>;
    const userAccount = Keypair.generate();
    const attacker = Keypair.generate();
    const attackerId = new anchor.BN(attacker.publicKey.toBuffer()[0]);

    before(async () => {
      const sig = await provider.connection.requestAirdrop(attacker.publicKey, 10e9);
      await provider.connection.confirmTransaction(sig);

      await program.methods.initializeUser(attackerId)
        .accounts({
          user: userAccount.publicKey,
          signer: attacker.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([userAccount, attacker])
        .rpc();
    });

    it("should reject invalid account types with Discriminator Error", async () => {
      try {
        await program.methods.adminWithdraw(new anchor.BN(100))
          .accounts({
            adminConfig: userAccount.publicKey,
            authority: attacker.publicKey,
          })
          .signers([attacker])
          .rpc();
        assert.fail("Transaction should have failed");
      } catch (err: any) {
        // Assertions for Account Discriminator mismatch
        const errorString = JSON.stringify(err);
        const isDiscriminatorError = 
          errorString.includes("AccountDiscriminatorMismatch") || 
          errorString.includes("Account discriminator") ||
          // Fallback for some localnet environments where specific codes might vary
          err.message.includes("AccountNotInitialized"); 
          
        assert.isTrue(isDiscriminatorError, `Unexpected error: ${err.message}`);
      }
    });
  });

  describe("Range Check Patch", () => {
    const program = anchor.workspace.RangeCheckFixed as Program<RangeCheckFixed>;
    
    const [character] = PublicKey.findProgramAddressSync(
      [Buffer.from("char"), provider.wallet.publicKey.toBuffer()],
      program.programId
    );
    
    before(async () => {
      await program.methods.initialize()
        .accounts({
          character,
          signer: provider.wallet.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();
    });

    it("should reject levels exceeding MAX_LEVEL (100)", async () => {
      try {
        await program.methods.setLevel(255)
          .accounts({
            character,
            signer: provider.wallet.publicKey,
          })
          .rpc();
        assert.fail("Transaction should have failed");
      } catch (err: any) {
        assert.include(err.message, "Level must be between 1 and 100");
      }
    });
  });

  describe("Duplicate Account Patch", () => {
    const program = anchor.workspace.DuplicateAccountFixed as Program<DuplicateAccountFixed>;
    const wallet = Keypair.generate();

    before(async () => {
      await program.methods.initialize()
        .accounts({
          wallet: wallet.publicKey,
          signer: provider.wallet.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([wallet])
        .rpc();
    });

    it("should prevent self-transfer via key check", async () => {
      try {
        await program.methods.transfer(new anchor.BN(1000))
          .accounts({
            from: wallet.publicKey,
            to: wallet.publicKey,
          })
          .rpc();
        assert.fail("Transaction should have failed");
      } catch (err: any) {
        assert.include(err.message, "Source and destination accounts must be different");
      }
    });
  });
});
