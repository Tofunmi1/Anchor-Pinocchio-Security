import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { assert } from "chai";
import { Keypair, SystemProgram } from "@solana/web3.js";
import { TruncationVulnerable } from "../target/types/truncation_vulnerable";
import { TruncationFixed } from "../target/types/truncation_fixed";

describe("07 - Type Casting Truncation", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  describe("Vulnerable: Silent Truncation", () => {
    const program = anchor.workspace.TruncationVulnerable as Program<TruncationVulnerable>;
    const state = Keypair.generate();

    it("Initialize with large value", async () => {
      // Use a value that when multiplied will exceed u64::MAX
      const largeValue = new anchor.BN("10000000000000000000"); // 10^19
      
      await program.methods
        .initialize(largeValue)
        .accounts({
          state: state.publicKey,
          authority: provider.wallet.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([state])
        .rpc();
    });

    it("VULNERABILITY: Result truncated silently", async () => {
      // Multiply by 2 - result should be 2*10^19 but u64::MAX is ~1.8*10^19
      const multiplier = new anchor.BN(2);
      
      await program.methods
        .calculate(multiplier)
        .accounts({
          state: state.publicKey,
          authority: provider.wallet.publicKey,
        })
        .rpc();

      const account = await program.account.state.fetch(state.publicKey);
      
      console.log("\n  VULNERABILITY:");
      console.log("  - Original value: 10^19");
      console.log("  - Multiplied by: 2");
      console.log("  - Expected: 2*10^19 (exceeds u64::MAX)");
      console.log("  - Got (truncated):", account.result.toString());
      console.log("  - u64::MAX is: 18446744073709551615");
      
      // The result should NOT equal the correct mathematical answer
      // because truncation occurred
      assert.notEqual(
        account.result.toString(),
        "20000000000000000000"
      );
    });
  });

  describe("Fixed: try_from prevents truncation", () => {
    const program = anchor.workspace.TruncationFixed as Program<TruncationFixed>;
    const state = Keypair.generate();

    it("Initialize with large value", async () => {
      const largeValue = new anchor.BN("10000000000000000000");
      
      await program.methods
        .initialize(largeValue)
        .accounts({
          state: state.publicKey,
          authority: provider.wallet.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([state])
        .rpc();
    });

    it("FIX: Calculation rejected when overflow would occur", async () => {
      const multiplier = new anchor.BN(2);
      
      try {
        await program.methods
          .calculate(multiplier)
          .accounts({
            state: state.publicKey,
            authority: provider.wallet.publicKey,
          })
          .rpc();
          
        assert.fail("Should have failed");
      } catch (err: any) {
        console.log("\n  FIX:");
        console.log("  - Original value: 10^19");
        console.log("  - Multiplied by: 2");
        console.log("  - Result would exceed u64::MAX");
        console.log("  - Program rejected with: Overflow error");
        
        assert.ok(err.message.includes("Overflow") || JSON.stringify(err).includes("Overflow"));
      }
    });

    it("FIX: Small calculation succeeds", async () => {
      const state2 = Keypair.generate();
      const smallValue = new anchor.BN(1000);
      
      await program.methods
        .initialize(smallValue)
        .accounts({
          state: state2.publicKey,
          authority: provider.wallet.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([state2])
        .rpc();

      await program.methods
        .calculate(new anchor.BN(5))
        .accounts({
          state: state2.publicKey,
          authority: provider.wallet.publicKey,
        })
        .rpc();

      const account = await program.account.state.fetch(state2.publicKey);
      
      console.log("\n  FIX:");
      console.log("  - 1000 * 5 = 5000 (fits in u64)");
      console.log("  - Result:", account.result.toString());
      
      assert.equal(account.result.toString(), "5000");
    });
  });
});
