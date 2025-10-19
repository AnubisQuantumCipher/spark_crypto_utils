pragma SPARK_Mode (On);
with SparkPass.Types; use SparkPass.Types;

package SparkPass.Crypto.Self_Test is
   type Stage_Status is (Succeeded, Failed, Skipped);
   type Tamper_Status is (Detected, Not_Detected);

   --  Individual test result categories
   type Report is record
      --  Layer 1: Cryptographic Primitives
      Argon2_Status             : Stage_Status := Failed;
      Argon2_Duration           : Duration := 0.0;
      Argon2_Used_Strong_Params : Boolean := True;
      HKDF_Status               : Stage_Status := Failed;
      AEAD_Status                : Stage_Status := Failed;
      MLKEM_Status              : Stage_Status := Failed;
      MLDSA_Status              : Stage_Status := Failed;
      MLDSA_Tamper              : Tamper_Status := Not_Detected;
      Random_Status             : Stage_Status := Failed;

      --  Layer 2: SparkPass Cryptography
      Shamir_Status             : Stage_Status := Failed;
      ReedSolomon_Status        : Stage_Status := Failed;
      Nonce_Status              : Stage_Status := Failed;
      Wrapping_Status           : Stage_Status := Failed;
      Zeroization_Status        : Stage_Status := Failed;

      --  Layer 3: Vault Operations
      KeyArena_Status           : Stage_Status := Failed;
      Policy_Status             : Stage_Status := Failed;

      --  Layer 4: Platform Integration (may be skipped)
      Platform_Status           : Stage_Status := Skipped;

      --  Overall timing
      Total_Duration            : Duration := 0.0;
   end record;

   --  Test modes
   type Test_Mode is
     (Fast,           --  Essential tests only (< 5 seconds)
      Comprehensive,  --  All tests including slow ones (< 15 seconds)
      Benchmark);     --  With detailed timing measurements

   --  Check if all required tests passed
   function Passed (R : Report) return Boolean
     with
       Global  => null,
       Depends => (Passed'Result => R);

   --  Run self-tests with specified mode
   procedure Run
     (Result : out Report;
      Mode   : in  Test_Mode := Fast)
     with
       Global  => null,
       Depends => (Result => Mode);

   --  Format test report as human-readable output
   --  Returns: Formatted string with test results
   --  Max_Lines: Maximum number of output lines
   function Format_Report
     (R : Report;
      Mode : Test_Mode;
      Verbose : Boolean := False)
     return String
     with
       Global => null;

end SparkPass.Crypto.Self_Test;
