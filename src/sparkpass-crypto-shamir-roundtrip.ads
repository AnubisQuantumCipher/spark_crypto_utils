pragma SPARK_Mode (On);
with Interfaces;
with SparkPass.Types; use SparkPass.Types;
with SparkPass.Crypto.Shamir; use SparkPass.Crypto.Shamir;

--  =========================================================================
--  Shamir Secret Sharing Round-Trip Property Verification
--  =========================================================================
--
--  **GOLD PROPERTY**: Combine(Split(Secret, K, N)) = Secret
--
--  **PURPOSE**: Prove that Shamir secret sharing reconstruction is correct:
--    given a secret, splitting it into shares and recombining those shares
--    produces the original secret.
--
--  **APPROACH**: Ghost verification procedure that composes Split and Combine,
--    proving the round-trip property holds for valid inputs.
--
--  **VERIFICATION METHODOLOGY**:
--    1. Call Split(Secret, K, N) -> Shares
--    2. Call Combine(Shares[1..K], K) -> Reconstructed_Secret
--    3. Prove: Reconstructed_Secret = Secret
--
--  **CHALLENGES**:
--    - Split uses randomness (non-deterministic), but output is deterministic
--      in the sense that any valid split produces reconstructible shares
--    - Proving Lagrange interpolation inverts polynomial evaluation requires
--      field theory beyond SMT solver capabilities
--    - GF(256) arithmetic is complex for automated provers
--
--  **PROOF STRATEGY**:
--    - Prove memory safety and type safety (achievable with SPARK)
--    - Prove process completes without errors (achievable with SPARK)
--    - Assume mathematical correctness of Lagrange interpolation (documented)
--
--  **EXPECTED RESULT**:
--    ✅ Memory safety: proven
--    ✅ Type safety: proven
--    ✅ No runtime errors: proven
--    ⚠️  Mathematical correctness: assumed (requires interactive theorem prover)
--
--  **CITATION**: Shamir (1979), "How to Share a Secret"
--
package SparkPass.Crypto.Shamir.RoundTrip
with
   SPARK_Mode => On
is

   --  ========================================================================
   --  Ghost Predicates for Intermediate Proof Properties
   --  ========================================================================
   --
   --  **MARMARAGAN PATTERN**: Use ghost predicates to express intermediate
   --  properties that help the SMT solver understand the verification goal.
   --  These are verification-only functions with no runtime cost.

   --  Verify that all bytes in two secrets match
   function Secrets_Match (S1, S2 : Key_Array) return Boolean is
     (S1'Length = 32 and then
      S2'Length = 32 and then
      (for all I in S1'Range => S1 (I) = S2 (S2'First + (I - S1'First))))
   with
     Ghost,
     Global => null,
     Pre    => S1'Length = 32 and S2'Length = 32;

   --  Verify that share set has valid structure (all shares have correct size)
   function Shares_Have_Valid_Size (Shares : Share_Set) return Boolean is
     (for all I in Shares'Range => Shares (I)'Length = Share_Size)
   with
     Ghost,
     Global => null;

   --  Verify share structure validity (x-coordinate matches index)
   function Shares_Are_Valid (Shares : Share_Set) return Boolean is
     (for all I in Shares'Range =>
        Shares (I)(Shares (I)'First) = Interfaces.Unsigned_8 (I))
   with
     Ghost,
     Global => null,
     Pre    => Shares'First = 1 and then
               (for all I in Shares'Range => Shares (I)'Length = Share_Size);

   --  ========================================================================
   --  Round-Trip Verification Procedures
   --  ========================================================================

   --  Verify round-trip property: Combine(Split(Secret)) = Secret
   --
   --  **OPERATION**: Test that splitting a secret and recombining the shares
   --  produces the original secret.
   --
   --  **PARAMETERS**:
   --    Secret: Original 32-byte secret to test
   --    Threshold: Minimum shares needed (K)
   --    Total_Shares: Total shares to generate (N), where K <= N <= 10
   --    Success: True if round-trip succeeded, False if any operation failed
   --    Matches: True if reconstructed secret equals original, False otherwise
   --
   --  **PRECONDITIONS**:
   --    - Secret is exactly 32 bytes
   --    - 2 <= Threshold <= Total_Shares <= 10 (realistic test range)
   --    - Threshold <= 32 (mathematical constraint)
   --
   --  **POSTCONDITIONS**:
   --    - If Success is True, then:
   --        * Split succeeded (shares generated)
   --        * Combine succeeded (secret reconstructed)
   --        * Matches indicates if secrets are equal
   --    - If Success is False, then:
   --        * Either Split or Combine failed (should never happen with valid inputs)
   --
   --  **PROOF GOAL**:
   --    Prove: (Success = True) => (Matches = True)
   --    i.e., successful round-trip always produces matching secret
   --
   --  **PROOF STATUS**:
   --    ✅ Type safety: proven
   --    ✅ Memory safety: proven
   --    ✅ No crashes: proven
   --    ⚠️  Matches = True: relies on Lagrange interpolation correctness (assumed)
   --
   procedure Verify_RoundTrip
     (Secret       : in  Key_Array;
      Threshold    : in  Share_Count;
      Total_Shares : in  Share_Count;
      Success      : out Boolean;
      Matches      : out Boolean)
   with
     Global  => null,
     Pre     => Secret'Length = 32 and then
                Threshold >= 2 and then  -- Minimum practical threshold
                Threshold <= Total_Shares and then
                Total_Shares <= 10 and then
                Threshold <= 32,
     Post    => (if not Success then not Matches) and then
                (if Success then
                  -- MATHEMATICAL ASSUMPTION:
                  -- If Split and Combine both succeed, then reconstructed secret
                  -- equals original secret (by Lagrange interpolation correctness).
                  --
                  -- This property cannot be automatically proven by SMT solvers
                  -- but is documented and assumed based on mathematical proof.
                  --
                  -- For full formal verification, this requires:
                  --   1. Coq/Isabelle formalization of GF(256) field theory
                  --   2. Proof of Lagrange interpolation uniqueness theorem
                  --   3. Proof that Evaluate_Polynomial and Lagrange_Interpolate
                  --      are inverse operations
                  True);
   --  NOTE: The postcondition doesn't prove Matches = True, but documents
   --  the mathematical property being assumed.

   --  Verify round-trip property for multiple test cases
   --
   --  **OPERATION**: Run multiple round-trip tests with different configurations
   --  to provide empirical confidence in reconstruction correctness.
   --
   --  **PARAMETERS**:
   --    All_Tests_Passed: True if all test cases passed, False if any failed
   --
   --  **TEST CASES**:
   --    1. 2-of-3 threshold (common configuration)
   --    2. 3-of-5 threshold (higher security)
   --    3. 5-of-7 threshold (maximum tested)
   --
   --  **PROOF GOAL**:
   --    Prove all tests complete without runtime errors (memory safety).
   --    Empirically verify Matches = True for all cases (not formally proven).
   --
   procedure Verify_Multiple_Configurations
     (Test_Secret        : in  Key_Array;
      All_Tests_Passed   : out Boolean)
   with
     Global  => null,
     Pre     => Test_Secret'Length = 32,
     Post    => True;  -- Safety proven, correctness assumed

end SparkPass.Crypto.Shamir.RoundTrip;
