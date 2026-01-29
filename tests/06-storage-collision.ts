import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { assert } from "chai";
import { Keypair, SystemProgram } from "@solana/web3.js";
import { StorageCollisionV1 } from "../target/types/storage_collision_v1";
import { StorageCollisionV2 } from "../target/types/storage_collision_v2";
import { StorageCollisionFixed } from "../target/types/storage_collision_fixed";

/**
 * Storage Collision Vulnerability Test Suite
 * 
 * This test demonstrates how inserting fields in the middle of a struct
 * during a program upgrade can cause storage collisions, leading to
 * privilege escalation vulnerabilities.
 * 
 * Scenario:
 * 1. V1 creates a vault with: balance, owner, is_active
 * 2. V2 (buggy) inserts is_admin BEFORE is_active
 * 3. V2 reads V1's is_active byte as is_admin -> privilege escalation!
 * 4. Fixed version appends is_admin AFTER is_active -> no collision
 */
describe("06 - Program Upgrade: Storage Collision Vulnerability", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const programV1 = anchor.workspace.StorageCollisionV1 as Program<StorageCollisionV1>;
  const programV2 = anchor.workspace.StorageCollisionV2 as Program<StorageCollisionV2>;
  const programFixed = anchor.workspace.StorageCollisionFixed as Program<StorageCollisionFixed>;

  const vaultKeypair = Keypair.generate();
  const user = provider.wallet;
  const INITIAL_BALANCE = new anchor.BN(1000);

  describe("Setup: Create V1 Vault", () => {
    it("should create a vault with V1 layout (balance, owner, is_active)", async () => {
      await programV1.methods.createVault(INITIAL_BALANCE)
        .accounts({
          vault: vaultKeypair.publicKey,
          owner: user.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([vaultKeypair])
        .rpc();

      // Verify the vault was created correctly
      const vaultData = await programV1.account.vault.fetch(vaultKeypair.publicKey);
      assert.equal(vaultData.balance.toNumber(), 1000, "Balance should be 1000");
      assert.equal(vaultData.owner.toString(), user.publicKey.toString(), "Owner should match");
      assert.isTrue(vaultData.isActive, "Vault should be active");

      console.log("\n  V1 Vault Created:");
      console.log("    - Balance:", vaultData.balance.toString());
      console.log("    - Owner:", vaultData.owner.toString().slice(0, 16) + "...");
      console.log("    - is_active:", vaultData.isActive);
      console.log("    - (is_admin field does not exist in V1)");
    });
  });

  describe("Vulnerability: V2 Storage Collision Exploit", () => {
    it("should allow unauthorized admin access due to storage collision", async () => {
      // V2 reads the vault with a different struct layout.
      // The is_active byte (0x01) is now interpreted as is_admin.
      // This means ANY active V1 vault is now treated as an admin vault!

      try {
        await programV2.methods.adminWithdraw(new anchor.BN(100))
          .accounts({
            vault: vaultKeypair.publicKey,
            admin: user.publicKey,
          })
          .rpc();

        console.log("\n  VULNERABILITY EXPLOITED:");
        console.log("    - Non-admin user successfully called admin_withdraw");
        console.log("    - V2 misread V1's is_active (0x01) as is_admin (true)");
        console.log("    - Any active V1 user can now act as admin!");

      } catch (err) {
        assert.fail(`Expected exploit to succeed, but got error: ${err}`);
      }
    });

    it("should also allow unauthorized emergency_pause", async () => {
      try {
        await programV2.methods.emergencyPause()
          .accounts({
            vault: vaultKeypair.publicKey,
            admin: user.publicKey,
          })
          .rpc();

        console.log("\n  ADDITIONAL EXPLOIT:");
        console.log("    - Non-admin triggered emergency_pause");
        console.log("    - Same storage collision vulnerability applies");

      } catch (err) {
        assert.fail(`Expected exploit to succeed, but got error: ${err}`);
      }
    });
  });

  describe("Fix: Append-Only Field Addition", () => {
    it("should reject unauthorized admin access with correct layout", async () => {
      // The fixed version appends is_admin AFTER is_active.
      // When reading V1 data, is_admin reads from padding (0x00) = false.
      // This correctly prevents privilege escalation.

      try {
        await programFixed.methods.adminWithdraw(new anchor.BN(100))
          .accounts({
            vault: vaultKeypair.publicKey,
            admin: user.publicKey,
          })
          .rpc();

        assert.fail("Fixed version should have rejected the transaction");

      } catch (err: any) {
        const errorString = JSON.stringify(err);
        assert.include(
          errorString, 
          "does not have admin privileges",
          "Should fail with NotAdmin error"
        );

        console.log("\n  FIX VERIFIED:");
        console.log("    - admin_withdraw correctly rejected");
        console.log("    - is_admin reads from padding (0x00) = false");
        console.log("    - Append-only upgrade pattern prevents collision");
      }
    });
  });

  describe("Byte-Level Verification", () => {
    it("should demonstrate the exact byte layout difference", async () => {
      // Read raw account data to show the byte-level storage layout
      const accountInfo = await provider.connection.getAccountInfo(vaultKeypair.publicKey);
      
      if (!accountInfo) {
        assert.fail("Account not found");
        return;
      }

      const data = accountInfo.data;
      
      console.log("\n  Raw Account Data Analysis:");
      console.log("    - Total size:", data.length, "bytes");
      console.log("    - Discriminator (0-8):", data.slice(0, 8).toString("hex"));
      console.log("    - Balance (8-16):", new anchor.BN(data.slice(8, 16), "le").toString());
      console.log("    - Owner (16-48):", data.slice(16, 48).toString("hex").slice(0, 16) + "...");
      console.log("    - Byte at offset 48:", `0x${data[48].toString(16).padStart(2, "0")}`, 
                  data[48] === 1 ? "(V1: is_active=true, V2: is_admin=true!)" : "");
      console.log("    - Byte at offset 49:", `0x${data[49].toString(16).padStart(2, "0")}`,
                  "(padding in V1, is_active in V2, is_admin in Fixed)");

      // Verify the critical byte
      assert.equal(data[48], 1, "Byte 48 should be 0x01 (is_active = true)");
      assert.equal(data[49], 0, "Byte 49 should be 0x00 (padding)");
    });
  });
});
