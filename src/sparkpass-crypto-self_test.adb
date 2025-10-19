pragma SPARK_Mode (Off);  -- Uses Ada.Real_Time and address clauses for testing
with Ada.Real_Time;
with Interfaces; use type Interfaces.Unsigned_8;
with SparkPass.Crypto.Argon2id;
with SparkPass.Crypto.ChaCha20Poly1305;
with SparkPass.Crypto.HKDF;
with SparkPass.Crypto.MLDSA;
with SparkPass.Crypto.MLKEM;
with SparkPass.Crypto.Random;
with SparkPass.Crypto.Zeroize;
with SparkPass.Crypto.Shamir;
with SparkPass.Crypto.ReedSolomon; use type SparkPass.Crypto.ReedSolomon.Decode_Status;
with SparkPass.Crypto.Nonce;
with SparkPass.Crypto.Wrapping;
with SparkPass.Vault.KeyArena; use type SparkPass.Vault.KeyArena.Parse_Status;
with SparkPass.Vault.Policy;

package body SparkPass.Crypto.Self_Test is

   function Passed (R : Report) return Boolean is
   begin
      return
        (R.Argon2_Status = Succeeded)
        and then (R.HKDF_Status = Succeeded)
        and then (R.AEAD_Status = Succeeded)
        and then (R.MLKEM_Status = Succeeded)
        and then (R.MLDSA_Status = Succeeded)
        and then (R.MLDSA_Tamper = Detected)
        and then (R.Random_Status = Succeeded)
        and then (R.Shamir_Status = Succeeded)
        and then (R.ReedSolomon_Status = Succeeded or R.ReedSolomon_Status = Skipped)
        and then (R.Nonce_Status = Succeeded)
        and then (R.Wrapping_Status = Succeeded)
        and then (R.Zeroization_Status = Succeeded)
        and then (R.KeyArena_Status = Succeeded or R.KeyArena_Status = Skipped)
        and then (R.Policy_Status = Succeeded);
        --  Platform_Status may be Skipped (not required for pass)
        --  ReedSolomon and KeyArena may be Skipped in Fast mode
   end Passed;

   procedure Test_Random (Status : out Stage_Status) is
      Buf1 : Byte_Array (1 .. 32) := (others => 0);
      Buf2 : Byte_Array (1 .. 32) := (others => 0);
      All_Zero : Boolean := True;
      All_Same : Boolean := True;
   begin
      Status := Failed;

      --  Test 1: Fill generates non-zero output
      SparkPass.Crypto.Random.Fill (Buf1);

      for I in Buf1'Range loop
         if Buf1 (I) /= 0 then
            All_Zero := False;
            exit;
         end if;
      end loop;

      if All_Zero then
         return;  --  RNG producing all zeros is broken
      end if;

      --  Test 2: Two calls to Fill produce different output
      SparkPass.Crypto.Random.Fill (Buf2);

      for I in Buf1'Range loop
         if Buf1 (I) /= Buf2 (I) then
            All_Same := False;
            exit;
         end if;
      end loop;

      if All_Same then
         return;  --  RNG producing identical output is broken
      end if;

      Status := Succeeded;
      SparkPass.Crypto.Zeroize.Wipe (Buf1);
      SparkPass.Crypto.Zeroize.Wipe (Buf2);
   end Test_Random;

   procedure Test_Shamir (Status : out Stage_Status) is
      Root_Key : Key_Array := (others => 0);
      Reconstructed : Key_Array := (others => 0);
      Shares_2_of_2 : SparkPass.Crypto.Shamir.Share_Set (1 .. 2);
      Shares_3_of_5 : SparkPass.Crypto.Shamir.Share_Set (1 .. 5);
      Shares_Subset : SparkPass.Crypto.Shamir.Share_Set (1 .. 3);
      Success : Boolean := False;
   begin
      Status := Failed;

      --  Initialize root key with test pattern
      for I in Root_Key'Range loop
         Root_Key (I) := U8 ((I * 7) mod 256);
      end loop;

      --  Test 1: 2-of-2 split and reconstruct
      SparkPass.Crypto.Shamir.Split
        (Root_Key     => Root_Key,
         Threshold    => 2,
         Total_Shares => 2,
         Shares       => Shares_2_of_2,
         Success      => Success);

      if not Success then
         return;
      end if;

      SparkPass.Crypto.Shamir.Combine
        (Shares    => Shares_2_of_2,
         Threshold => 2,
         Root_Key  => Reconstructed,
         Success   => Success);

      if not Success then
         return;
      end if;

      if not SparkPass.Crypto.Zeroize.Equal (Root_Key, Reconstructed) then
         return;  --  Reconstruction failed
      end if;

      --  Test 2: 3-of-5 split
      SparkPass.Crypto.Shamir.Split
        (Root_Key     => Root_Key,
         Threshold    => 3,
         Total_Shares => 5,
         Shares       => Shares_3_of_5,
         Success      => Success);

      if not Success then
         return;
      end if;

      --  Test 3: Reconstruct with first 3 shares
      for I in 1 .. 3 loop
         Shares_Subset (I) := Shares_3_of_5 (I);
      end loop;

      SparkPass.Crypto.Shamir.Combine
        (Shares    => Shares_Subset,
         Threshold => 3,
         Root_Key  => Reconstructed,
         Success   => Success);

      if not Success then
         return;
      end if;

      if not SparkPass.Crypto.Zeroize.Equal (Root_Key, Reconstructed) then
         return;
      end if;

      Status := Succeeded;

      --  Cleanup
      SparkPass.Crypto.Zeroize.Wipe (Root_Key);
      SparkPass.Crypto.Zeroize.Wipe (Reconstructed);
      SparkPass.Crypto.Shamir.Wipe_Share_Set (Shares_2_of_2);
      SparkPass.Crypto.Shamir.Wipe_Share_Set (Shares_3_of_5);
      SparkPass.Crypto.Shamir.Wipe_Share_Set (Shares_Subset);
   end Test_Shamir;

   procedure Test_ReedSolomon (Status : out Stage_Status) is
      Data : SparkPass.Crypto.ReedSolomon.Data_Block;
      Parity : SparkPass.Crypto.ReedSolomon.Parity_Block;
      Codeword : SparkPass.Crypto.ReedSolomon.Codeword_Block;
      Corrupted : SparkPass.Crypto.ReedSolomon.Codeword_Block;
      Corrected_Count : Natural := 0;
      Success : Boolean := False;
      Has_Errors : Boolean := False;
      Decode_Result : SparkPass.Crypto.ReedSolomon.Decode_Status;
   begin
      Status := Failed;

      --  Initialize test data
      for I in Data'Range loop
         Data (I) := U8 ((I * 13) mod 256);
      end loop;

      --  Test 1: Encode
      SparkPass.Crypto.ReedSolomon.Encode (Data, Parity, Success);

      if not Success then
         return;
      end if;

      --  Construct codeword (systematic: data || parity)
      for I in Data'Range loop
         Codeword (I) := Data (I);
      end loop;

      for I in Parity'Range loop
         Codeword (Data'Length + I) := Parity (I);
      end loop;

      --  Test 2: Syndrome check (no errors)
      SparkPass.Crypto.ReedSolomon.Compute_Syndromes (Codeword, Has_Errors);

      if Has_Errors then
         return;  --  False positive error detection
      end if;

      --  Test 3: Introduce 8 errors (within correction capacity)
      Corrupted := Codeword;
      for I in 1 .. 8 loop
         Corrupted (I * 10) := Corrupted (I * 10) xor 16#FF#;
      end loop;

      --  Test 4: Correct errors
      SparkPass.Crypto.ReedSolomon.Decode
        (Codeword        => Corrupted,
         Corrected_Count => Corrected_Count,
         Status          => Decode_Result);

      if Decode_Result /= SparkPass.Crypto.ReedSolomon.Success then
         return;
      end if;

      if Corrected_Count /= 8 then
         return;  --  Wrong number of corrections
      end if;

      --  Test 5: Verify correction
      if not SparkPass.Crypto.Zeroize.Equal (Corrupted, Codeword) then
         return;
      end if;

      Status := Succeeded;
   end Test_ReedSolomon;

   procedure Test_Nonce_Derivation (Status : out Stage_Status) is
      Counter1 : constant U64 := 1;
      Counter2 : constant U64 := 2;
      Entry_ID1 : Entry_Id_Array := (others => 1);
      Entry_ID2 : Entry_Id_Array := (others => 2);
      Nonce1 : Nonce_Array;
      Nonce2 : Nonce_Array;
      Nonce3 : Nonce_Array;
      Nonce4 : Nonce_Array;
   begin
      Status := Failed;

      --  Test 1: Determinism (same inputs -> same output)
      Nonce1 := SparkPass.Crypto.Nonce.Derive_Nonce
        (Counter  => Counter1,
         Entry_ID => Entry_ID1,
         Domain   => SparkPass.Crypto.Nonce.Entry_Data);

      Nonce2 := SparkPass.Crypto.Nonce.Derive_Nonce
        (Counter  => Counter1,
         Entry_ID => Entry_ID1,
         Domain   => SparkPass.Crypto.Nonce.Entry_Data);

      if not SparkPass.Crypto.Zeroize.Equal (Nonce1, Nonce2) then
         return;  --  Nonce derivation not deterministic
      end if;

      --  Test 2: Counter injectivity
      Nonce3 := SparkPass.Crypto.Nonce.Derive_Nonce
        (Counter  => Counter2,
         Entry_ID => Entry_ID1,
         Domain   => SparkPass.Crypto.Nonce.Entry_Data);

      if SparkPass.Crypto.Zeroize.Equal (Nonce1, Nonce3) then
         return;  --  Different counters produced same nonce
      end if;

      --  Test 3: Entry_ID injectivity
      Nonce4 := SparkPass.Crypto.Nonce.Derive_Nonce
        (Counter  => Counter1,
         Entry_ID => Entry_ID2,
         Domain   => SparkPass.Crypto.Nonce.Entry_Data);

      if SparkPass.Crypto.Zeroize.Equal (Nonce1, Nonce4) then
         return;  --  Different entry IDs produced same nonce
      end if;

      --  Test 4: Domain separation
      Nonce4 := SparkPass.Crypto.Nonce.Derive_Nonce
        (Counter  => Counter1,
         Entry_ID => Entry_ID1,
         Domain   => SparkPass.Crypto.Nonce.Entry_Metadata);

      if SparkPass.Crypto.Zeroize.Equal (Nonce1, Nonce4) then
         return;  --  Different domains produced same nonce
      end if;

      Status := Succeeded;
   end Test_Nonce_Derivation;

   procedure Test_Wrapping (Status : out Stage_Status) is
      Root_Key : Key_Array := (others => 0);
      Device_Secret : Key_Array := (others => 0);
      Wrapped : SparkPass.Crypto.Wrapping.Wrapped_Key;
      Unwrapped : Key_Array := (others => 0);
      Success : Boolean := False;
   begin
      Status := Failed;

      --  Initialize keys
      for I in Root_Key'Range loop
         Root_Key (I) := U8 ((I * 11) mod 256);
      end loop;

      for I in Device_Secret'Range loop
         Device_Secret (I) := U8 ((I * 17) mod 256);
      end loop;

      --  Test: Wrap and unwrap with Touch ID wrapping (generic KEK wrap)
      SparkPass.Crypto.Wrapping.Wrap_With_Touch_ID
        (Root_Key      => Root_Key,
         Device_Secret => Device_Secret,
         Wrapped       => Wrapped,
         Success       => Success);

      if not Success then
         return;
      end if;

      SparkPass.Crypto.Wrapping.Unwrap_With_Touch_ID
        (Wrapped       => Wrapped,
         Device_Secret => Device_Secret,
         Root_Key      => Unwrapped,
         Success       => Success);

      if not Success then
         return;
      end if;

      if not SparkPass.Crypto.Zeroize.Equal (Root_Key, Unwrapped) then
         return;  --  Unwrapped key doesn't match original
      end if;

      Status := Succeeded;

      SparkPass.Crypto.Zeroize.Wipe (Root_Key);
      SparkPass.Crypto.Zeroize.Wipe (Device_Secret);
      SparkPass.Crypto.Zeroize.Wipe (Unwrapped);
      SparkPass.Crypto.Wrapping.Wipe_Wrapped_Key (Wrapped);
   end Test_Wrapping;

   procedure Test_KeyArena (Status : out Stage_Status) is
      Arena : SparkPass.Vault.KeyArena.Key_Arena;
      Buffer : Byte_Array (1 .. SparkPass.Vault.KeyArena.KeyArena_Max_Size) := (others => 0);
      Arena2 : SparkPass.Vault.KeyArena.Key_Arena;
      Actual_Size : Natural := 0;
      Parse_Result : SparkPass.Vault.KeyArena.Parse_Status;
      Root_Key : Key_Array := (others => 42);
      Passphrase : constant Byte_Array := (1 => 116, 2 => 101, 3 => 115, 4 => 116, 5 => 112, 6 => 97, 7 => 115, 8 => 115, 9 => 119, 10 => 111, 11 => 114, 12 => 100); -- "testpassword"
      Salt : Salt_Array := (others => 0);
      KDF_Params : SparkPass.Crypto.Argon2id.Parameters;
      Success : Boolean := False;
   begin
      Status := Failed;

      --  Initialize KDF parameters for passphrase wrap (Wrap A)
      --  Use minimal parameters for fast self-test
      KDF_Params.Memory_Cost := 65_536;  -- 64 MiB (fast for testing)
      KDF_Params.Iterations  := 1;
      KDF_Params.Parallelism := 1;
      SparkPass.Crypto.Random.Fill (KDF_Params.Salt);
      SparkPass.Crypto.Random.Fill (Salt);

      --  Initialize Arena with Wrap A (passphrase wrap, required by policy)
      SparkPass.Crypto.Wrapping.Wrap_With_Passphrase
        (Root_Key   => Root_Key,
         Passphrase => Passphrase,
         Salt       => Salt,
         KDF_Params => KDF_Params,
         Wrapped    => Arena.Wrap_A,
         Success    => Success);

      if not Success then
         return;
      end if;

      --  Mark Wrap A as present (Wrap_With_Passphrase sets Arena.Wrap_A.Present)
      Arena.Wrap_A_Present := Arena.Wrap_A.Present;

      --  Test: Serialize
      SparkPass.Vault.KeyArena.Serialize
        (Arena       => Arena,
         Buffer      => Buffer,
         Actual_Size => Actual_Size,
         Status      => Parse_Result);

      if Parse_Result /= SparkPass.Vault.KeyArena.Ok then
         return;
      end if;

      if Actual_Size = 0 or Actual_Size > SparkPass.Vault.KeyArena.KeyArena_Max_Size then
         return;
      end if;

      --  Test: Deserialize
      SparkPass.Vault.KeyArena.Deserialize
        (Buffer => Buffer (1 .. Actual_Size),
         Arena  => Arena2,
         Status => Parse_Result);

      if Parse_Result /= SparkPass.Vault.KeyArena.Ok then
         return;
      end if;

      --  Test: Policy validation
      if not SparkPass.Vault.KeyArena.Is_Valid_Policy (Arena2) then
         return;
      end if;

      Status := Succeeded;

      SparkPass.Vault.KeyArena.Wipe_Arena (Arena);
      SparkPass.Vault.KeyArena.Wipe_Arena (Arena2);
      SparkPass.Crypto.Zeroize.Wipe (Root_Key);
      SparkPass.Crypto.Zeroize.Wipe (Salt);
      SparkPass.Crypto.Zeroize.Wipe (KDF_Params.Salt);
   end Test_KeyArena;

   procedure Test_Policy (Status : out Stage_Status) is
      Policy1 : SparkPass.Vault.Policy.Combined_Policy;
      Policy2 : SparkPass.Vault.Policy.Combined_Policy;
      Buffer : SparkPass.Vault.Policy.Policy_Serialized_Array := (others => 0);
      Success : Boolean := False;
      Valid : Boolean := False;
      Error : SparkPass.Vault.Policy.Policy_Error;
      Message : SparkPass.Vault.Policy.Error_Message;
   begin
      Status := Failed;

      --  Test 1: Default policy is valid
      Policy1 := SparkPass.Vault.Policy.Default_Policy;

      if not SparkPass.Vault.Policy.Is_Safe_Policy (Policy1) then
         return;
      end if;

      --  Test 2: Validate policy
      SparkPass.Vault.Policy.Validate_Policy
        (Policy  => Policy1,
         Valid   => Valid,
         Error   => Error,
         Message => Message);

      if not Valid then
         return;
      end if;

      --  Test 3: Serialize
      SparkPass.Vault.Policy.Serialize_Policy
        (Policy  => Policy1,
         Buffer  => Buffer,
         Success => Success);

      if not Success then
         return;
      end if;

      --  Test 4: Deserialize
      SparkPass.Vault.Policy.Deserialize_Policy
        (Buffer  => Buffer,
         Policy  => Policy2,
         Success => Success);

      if not Success then
         return;
      end if;

      --  Test 5: Verify round-trip
      if not SparkPass.Vault.Policy.Is_Safe_Policy (Policy2) then
         return;
      end if;

      --  Test 6: Fast unlock policy with Touch ID
      Policy1 := SparkPass.Vault.Policy.With_Fast_Unlock
        (Base_Policy => SparkPass.Vault.Policy.Default_Policy,
         TTL_Minutes => 15,
         Scope       => SparkPass.Vault.Policy.Read_Only);

      if not SparkPass.Vault.Policy.Is_Safe_Policy (Policy1) then
         return;
      end if;

      --  Test 7: Touch ID never alone
      if not Policy1.Fast.Also_Passphrase then
         return;  --  Touch ID without passphrase is invalid
      end if;

      --  Test 8: Unlock logic
      if not SparkPass.Vault.Policy.Allows_Unlock
        (Policy         => Policy1,
         Has_Passphrase => True,
         Has_Recovery   => False,
         Has_Shamir     => False,
         Shamir_Count   => 0,
         Has_TouchID    => False)
      then
         return;  --  Passphrase alone should work
      end if;

      Status := Succeeded;
   end Test_Policy;

   procedure Run (Result : out Report; Mode : in Test_Mode := Fast) is
      use Ada.Real_Time;

      Password : Byte_Array (1 .. 16);
      Params   : SparkPass.Crypto.Argon2id.Parameters;
      Derived  : Key_Array := (others => 0);
      Argon2_Success : Boolean := False;

      Salt : Byte_Array (1 .. 16);
      Info : constant Byte_Array (1 .. 8) := (1 => 16#01#, 2 => 16#02#, 3 => 16#03#, 4 => 16#04#, 5 => 16#05#, 6 => 16#06#, 7 => 16#07#, 8 => 16#08#);

      AES_Key   : Key_Array := (others => 0);
      Nonce     : Nonce_Array := (others => 0);
      Plain     : Byte_Array (1 .. 128) := (others => 0);
      Cipher    : Byte_Array (Plain'Range) := (others => 0);
      Decrypted : Byte_Array (Plain'Range) := (others => 0);
      Tag       : Tag_Array := (others => 0);

      Kem_Public : MLKem_Public_Key_Array;
      Kem_Secret : MLKem_Secret_Key_Array := (others => 0);
      Ciphertext : MLKem_Ciphertext_Array := (others => 0);
      Shared_Enc : MLKem_Shared_Key_Array := (others => 0);
      Shared_Dec : MLKem_Shared_Key_Array := (others => 0);
      Kem_Enc_Success : Boolean := False;
      Kem_Dec_Success : Boolean := False;

      Sig_Public : MLDsa_Public_Key_Array;
      Sig_Secret : MLDsa_Secret_Key_Array := (others => 0);
      Signature  : MLDsa_Signature_Array := (others => 0);
      Tampered   : MLDsa_Signature_Array := (others => 0);
      Message    : Byte_Array (1 .. 64) := (others => 0);
      Verify_OK  : Boolean := False;
      Tamper_OK  : Boolean := False;

      Start_Time : Time;
      Stop_Time  : Time;
      Overall_Start : Time;
   begin
      Overall_Start := Clock;

      Result :=
        (Argon2_Status             => Failed,
         Argon2_Duration           => 0.0,
         Argon2_Used_Strong_Params => True,
         HKDF_Status               => Failed,
         AEAD_Status                => Failed,
         MLKEM_Status              => Failed,
         MLDSA_Status              => Failed,
         MLDSA_Tamper              => Not_Detected,
         Random_Status             => Failed,
         Shamir_Status             => Failed,
         ReedSolomon_Status        => Failed,
         Nonce_Status              => Failed,
         Wrapping_Status           => Failed,
         Zeroization_Status        => Failed,
         KeyArena_Status           => Failed,
         Policy_Status             => Failed,
         Platform_Status           => Skipped,
         Total_Duration            => 0.0);

      --  Layer 1: Cryptographic Primitives

      --  Test Random
      Test_Random (Result.Random_Status);

      --  Test Argon2id
      for Index in Password'Range loop
         Password (Index) := U8 ((Index * 17) mod 256);
      end loop;

      SparkPass.Crypto.Random.Fill (Params.Salt);
      Start_Time := Clock;
      SparkPass.Crypto.Argon2id.Derive (Password, Params, Derived, Argon2_Success);
      Stop_Time := Clock;
      Result.Argon2_Duration := To_Duration (Stop_Time - Start_Time);

      if not Argon2_Success then
         Result.Argon2_Used_Strong_Params := False;
         Params.Memory_Cost := 65_536;
         Params.Iterations  := 1;
         Start_Time := Clock;
         SparkPass.Crypto.Argon2id.Derive (Password, Params, Derived, Argon2_Success);
         Stop_Time := Clock;
         Result.Argon2_Duration := To_Duration (Stop_Time - Start_Time);
      end if;

      if Argon2_Success then
         Result.Argon2_Status := Succeeded;
      end if;

      --  Test HKDF
      if Result.Argon2_Status = Succeeded then
         SparkPass.Crypto.Random.Fill (Salt);

         declare
            IKM_View : Byte_Array (Derived'Range);
            for IKM_View'Address use Derived (Derived'First)'Address;
            HKDF_Output : Byte_Array := SparkPass.Crypto.HKDF.Derive (IKM_View, Salt, Info, AES_Key'Length);
         begin
            for Index in AES_Key'Range loop
               AES_Key (Index) := HKDF_Output (HKDF_Output'First + (Index - AES_Key'First));
            end loop;
            Result.HKDF_Status := Succeeded;
            SparkPass.Crypto.Zeroize.Wipe (HKDF_Output);
         end;

         --  Test ChaCha20-Poly1305 (RFC 8439) AEAD
         if Result.HKDF_Status = Succeeded then
            SparkPass.Crypto.Random.Fill (Plain);
            SparkPass.Crypto.Random.Fill (Nonce);

            SparkPass.Crypto.ChaCha20Poly1305.Seal
              (Key        => AES_Key,
               Nonce      => Nonce,
               Plaintext  => Plain,
               AAD        => Salt,
               Ciphertext => Cipher,
               Tag        => Tag);

            SparkPass.Crypto.ChaCha20Poly1305.Open
              (Key        => AES_Key,
               Nonce      => Nonce,
               Ciphertext => Cipher,
               AAD        => Salt,
               Tag        => Tag,
               Plaintext  => Decrypted,
               Success    => Verify_OK);

            if Verify_OK and then SparkPass.Crypto.Zeroize.Equal (Decrypted, Plain) then
               Result.AEAD_Status := Succeeded;
            end if;
         end if;
      end if;

      --  Test ML-KEM
      if Result.AEAD_Status = Succeeded then
         SparkPass.Crypto.MLKEM.Keypair (Kem_Public, Kem_Secret);
         SparkPass.Crypto.MLKEM.Encapsulate (Kem_Public, Ciphertext, Shared_Enc, Kem_Enc_Success);
         if Kem_Enc_Success then
            SparkPass.Crypto.MLKEM.Decapsulate (Kem_Secret, Ciphertext, Shared_Dec, Kem_Dec_Success);
            if Kem_Dec_Success and then SparkPass.Crypto.Zeroize.Equal (Shared_Enc, Shared_Dec) then
               Result.MLKEM_Status := Succeeded;
            end if;
         end if;
      end if;

      --  Test ML-DSA
      if Result.MLKEM_Status = Succeeded then
         SparkPass.Crypto.MLDSA.Keypair (Sig_Public, Sig_Secret);
         SparkPass.Crypto.Random.Fill (Message);
         SparkPass.Crypto.MLDSA.Sign (Sig_Secret, Message, Signature);
         SparkPass.Crypto.MLDSA.Verify (Sig_Public, Message, Signature, Verify_OK);

         if Verify_OK then
            Result.MLDSA_Status := Succeeded;
            Tampered := Signature;
            Tampered (Tampered'First) := Tampered (Tampered'First) xor 1;
            SparkPass.Crypto.MLDSA.Verify (Sig_Public, Message, Tampered, Tamper_OK);
            if not Tamper_OK then
               Result.MLDSA_Tamper := Detected;
            end if;
         end if;
      end if;

      --  Layer 2: SparkPass Cryptography

      --  Test Shamir
      Test_Shamir (Result.Shamir_Status);

      --  Test Reed-Solomon (skip in Fast mode to save time)
      if Mode = Comprehensive or Mode = Benchmark then
         Test_ReedSolomon (Result.ReedSolomon_Status);
      else
         Result.ReedSolomon_Status := Skipped;
      end if;

      --  Test Nonce Derivation
      Test_Nonce_Derivation (Result.Nonce_Status);

      --  Test Wrapping
      Test_Wrapping (Result.Wrapping_Status);

      --  Layer 3: Vault Operations

      --  Test Key-Arena
      Test_KeyArena (Result.KeyArena_Status);

      --  Test Policy Engine
      Test_Policy (Result.Policy_Status);

      --  Layer 4: Platform Integration (skipped for now, requires platform-specific code)
      Result.Platform_Status := Skipped;

      --  Zeroization test
      SparkPass.Crypto.Argon2id.Zeroize (Derived);
      SparkPass.Crypto.Zeroize.Wipe_Key (AES_Key);
      SparkPass.Crypto.Zeroize.Wipe (Nonce);
      SparkPass.Crypto.Zeroize.Wipe (Plain);
      SparkPass.Crypto.Zeroize.Wipe (Cipher);
      SparkPass.Crypto.Zeroize.Wipe (Decrypted);
      SparkPass.Crypto.Zeroize.Wipe_Tag (Tag);
      SparkPass.Crypto.Zeroize.Wipe (Password);
      SparkPass.Crypto.Zeroize.Wipe (Salt);
      SparkPass.Crypto.Zeroize.Wipe (Message);
      SparkPass.Crypto.Zeroize.Wipe (Ciphertext);
      SparkPass.Crypto.Zeroize.Wipe (Shared_Enc);
      SparkPass.Crypto.Zeroize.Wipe (Shared_Dec);
      SparkPass.Crypto.Zeroize.Wipe (Kem_Secret);
      SparkPass.Crypto.Zeroize.Wipe (Sig_Secret);
      SparkPass.Crypto.Zeroize.Wipe (Signature);
      SparkPass.Crypto.Zeroize.Wipe (Tampered);

      if SparkPass.Crypto.Zeroize.Is_Zeroed (Derived)
        and then SparkPass.Crypto.Zeroize.Is_Zeroed (AES_Key)
        and then SparkPass.Crypto.Zeroize.Is_Zeroed (Nonce)
        and then SparkPass.Crypto.Zeroize.Is_Zeroed (Plain)
        and then SparkPass.Crypto.Zeroize.Is_Zeroed (Cipher)
        and then SparkPass.Crypto.Zeroize.Is_Zeroed (Decrypted)
        and then SparkPass.Crypto.Zeroize.Is_Zeroed (Tag)
        and then SparkPass.Crypto.Zeroize.Is_Zeroed (Password)
        and then SparkPass.Crypto.Zeroize.Is_Zeroed (Salt)
        and then SparkPass.Crypto.Zeroize.Is_Zeroed (Ciphertext)
        and then SparkPass.Crypto.Zeroize.Is_Zeroed (Shared_Enc)
        and then SparkPass.Crypto.Zeroize.Is_Zeroed (Shared_Dec)
        and then SparkPass.Crypto.Zeroize.Is_Zeroed (Kem_Secret)
        and then SparkPass.Crypto.Zeroize.Is_Zeroed (Sig_Secret)
        and then SparkPass.Crypto.Zeroize.Is_Zeroed (Signature)
        and then SparkPass.Crypto.Zeroize.Is_Zeroed (Tampered) then
         Result.Zeroization_Status := Succeeded;
      end if;

      --  Calculate total duration
      Stop_Time := Clock;
      Result.Total_Duration := To_Duration (Stop_Time - Overall_Start);
   end Run;

   function Format_Report
     (R : Report;
      Mode : Test_Mode;
      Verbose : Boolean := False)
     return String
   is
      pragma Unreferenced (Mode, Verbose);
   begin
      --  This is a placeholder - actual formatting would be done in CLI
      return "Test report formatting not implemented in package body";
   end Format_Report;

end SparkPass.Crypto.Self_Test;
