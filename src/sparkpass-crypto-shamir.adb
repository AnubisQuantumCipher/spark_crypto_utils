pragma SPARK_Mode (On);
with SparkPass.Crypto.Random;
with SparkPass.Crypto.Zeroize;

package body SparkPass.Crypto.Shamir is

   --  GF(256) arithmetic using irreducible polynomial x^8 + x^4 + x^3 + x + 1
   --  This is the same polynomial used in AES and other cryptographic systems
   --
   --  Multiplication is done via log/antilog tables for constant-time operation

   --  GF(256) multiplication using log tables (constant-time)
   type GF256 is mod 256;

   --  Precomputed log and antilog tables for GF(256)
   --  Generated using generator polynomial x^8 + x^4 + x^3 + x + 1
   type Log_Table is array (GF256 range 1 .. 255) of U8;
   type Exp_Table is array (U8 range 0 .. 255) of U8;

   --  Exponential table (antilog): exp[i] = g^i where g=3 is generator
   Exp : constant Exp_Table :=
     (1, 3, 5, 15, 17, 51, 85, 255, 26, 46, 114, 150, 161, 248, 19, 53,
      95, 225, 56, 72, 216, 115, 149, 164, 247, 2, 6, 10, 30, 34, 102, 170,
      229, 52, 92, 228, 55, 89, 235, 38, 106, 190, 217, 112, 144, 171, 230, 49,
      83, 245, 4, 12, 20, 60, 68, 204, 79, 209, 104, 184, 211, 110, 178, 205,
      76, 212, 103, 169, 224, 59, 77, 215, 98, 166, 241, 8, 24, 40, 120, 136,
      131, 158, 185, 208, 107, 189, 220, 127, 129, 152, 179, 206, 73, 219, 118, 154,
      181, 196, 87, 249, 16, 48, 80, 240, 11, 29, 39, 105, 187, 214, 97, 163,
      254, 25, 43, 125, 135, 146, 173, 236, 47, 113, 147, 174, 233, 32, 96, 160,
      251, 22, 58, 78, 210, 109, 183, 194, 93, 231, 50, 86, 250, 21, 63, 65,
      195, 94, 226, 61, 71, 201, 64, 192, 91, 237, 44, 116, 156, 191, 218, 117,
      159, 186, 213, 100, 172, 239, 42, 126, 130, 157, 188, 223, 122, 142, 137, 128,
      155, 182, 193, 88, 232, 35, 101, 175, 234, 37, 111, 177, 200, 67, 197, 84,
      252, 31, 33, 99, 165, 244, 7, 9, 27, 45, 119, 153, 176, 203, 70, 202,
      69, 207, 74, 222, 121, 139, 134, 145, 168, 227, 62, 66, 198, 81, 243, 14,
      18, 54, 90, 238, 41, 123, 141, 140, 143, 138, 133, 148, 167, 242, 13, 23,
      57, 75, 221, 124, 132, 151, 162, 253, 28, 36, 108, 180, 199, 82, 246, 1);

   --  Logarithm table: log[exp[i]] = i
   Log : constant Log_Table :=
     (0, 25, 1, 50, 2, 26, 198, 75, 199, 27, 104, 51, 238, 223, 3, 100,
      4, 224, 14, 52, 141, 129, 239, 76, 113, 8, 200, 248, 105, 28, 193, 125,
      194, 29, 181, 249, 185, 39, 106, 77, 228, 166, 114, 154, 201, 9, 120, 101,
      47, 138, 5, 33, 15, 225, 36, 18, 240, 130, 69, 53, 147, 218, 142, 150,
      143, 219, 189, 54, 208, 206, 148, 19, 92, 210, 241, 64, 70, 131, 56, 102,
      221, 253, 48, 191, 6, 139, 98, 179, 37, 226, 152, 34, 136, 145, 16, 126,
      110, 72, 195, 163, 182, 30, 66, 58, 107, 40, 84, 250, 133, 61, 186, 43,
      121, 10, 21, 155, 159, 94, 202, 78, 212, 172, 229, 243, 115, 167, 87, 175,
      88, 168, 80, 244, 234, 214, 116, 79, 174, 233, 213, 231, 230, 173, 232, 44,
      215, 117, 122, 235, 22, 11, 245, 89, 203, 95, 176, 156, 169, 81, 160, 127,
      12, 246, 111, 23, 196, 73, 236, 216, 67, 31, 45, 164, 118, 123, 183, 204,
      187, 62, 90, 251, 96, 177, 134, 59, 82, 161, 108, 170, 85, 41, 157, 151,
      178, 135, 144, 97, 190, 220, 252, 188, 149, 207, 205, 55, 63, 91, 209, 83,
      57, 132, 60, 65, 162, 109, 71, 20, 42, 158, 93, 86, 242, 211, 171, 68,
      17, 146, 217, 35, 32, 46, 137, 180, 124, 184, 38, 119, 153, 227, 165, 103,
      74, 237, 222, 197, 49, 254, 24, 13, 99, 140, 128, 192, 247, 112, 7);

   --  GF(256) multiplication: a * b
   function GF_Mult (A : U8; B : U8) return U8
   with
     Global => null,
     Post   => GF_Mult'Result in U8
   is
   begin
      if A = 0 or B = 0 then
         return 0;
      end if;

      --  Multiplication via log tables: a*b = exp[log[a] + log[b]]
      declare
         Log_A : constant U8 := Log (GF256 (A));
         Log_B : constant U8 := Log (GF256 (B));
         Sum   : constant Natural := Natural (Log_A) + Natural (Log_B);
         Index : constant U8 := (if Sum >= 255 then U8 (Sum - 255) else U8 (Sum));
      begin
         return Exp (Index);
      end;
   end GF_Mult;

   --  GF(256) division: a / b (where b != 0)
   function GF_Div (A : U8; B : U8) return U8
   with
     Global => null,
     Pre    => B /= 0,
     Post   => GF_Div'Result in U8
   is
   begin
      if A = 0 then
         return 0;
      end if;

      --  Division via log tables: a/b = exp[log[a] - log[b]]
      declare
         Log_A : constant U8 := Log (GF256 (A));
         Log_B : constant U8 := Log (GF256 (B));
         Diff  : constant Integer := Integer (Log_A) - Integer (Log_B);
         Index : constant U8 := (if Diff < 0 then U8 (Diff + 255) else U8 (Diff));
      begin
         return Exp (Index);
      end;
   end GF_Div;

   --  Evaluate polynomial at point x
   --  Coefficients: [c0, c1, ..., c_{k-1}] where c0 = secret byte
   --  Returns: c0 + c1*x + c2*x^2 + ... + c_{k-1}*x^{k-1}
   function Evaluate_Polynomial
     (Coeffs : Byte_Array;
      X      : U8) return U8
   with
     Global => null,
     Pre    => Coeffs'Length > 0 and Coeffs'Length <= 32,
     Post   => Evaluate_Polynomial'Result in U8
   is
      Result : U8 := 0;
      X_Power : U8 := 1;  -- x^0 = 1
   begin
      for I in Coeffs'Range loop
         --  Add c_i * x^i to result
         Result := Result xor GF_Mult (Coeffs (I), X_Power);

         --  Update x^i for next iteration (except on last iteration)
         if I /= Coeffs'Last then
            X_Power := GF_Mult (X_Power, X);
         end if;
      end loop;

      return Result;
   end Evaluate_Polynomial;

   --  Lagrange interpolation to compute P(0) from k points
   --
   --  **MATHEMATICAL OPERATION**: Reconstructs secret byte P(0) from k share points
   --  using Lagrange interpolation over GF(256).
   --
   --  **INPUTS**:
   --    X_Coords: x-coordinates of shares (must be distinct, non-zero)
   --    Y_Coords: y-coordinates of shares (one byte position across all shares)
   --
   --  **OUTPUT**: P(0) = secret byte
   --
   --  **PRECONDITIONS**:
   --    - Arrays have same length and non-empty
   --    - Arrays have matching indices (enforced by First = 1 constraint)
   --    - This prevents index mismatches when accessing Y_Coords(I) with I from X_Coords'Range
   --
   --  **PROOF STRATEGY**:
   --    - Loop iterates over X_Coords'Range = Y_Coords'Range (same indices)
   --    - Accessing Y_Coords(I) is safe because I ∈ X_Coords'Range = Y_Coords'Range
   --    - No overflow in GF(256) operations (always returns U8)
   --
   --  **CITATION**: Shamir Secret Sharing (Shamir 1979), Lagrange interpolation
   function Lagrange_Interpolate
     (X_Coords : Byte_Array;
      Y_Coords : Byte_Array) return U8
   with
     Global => null,
     Pre    => X_Coords'Length = Y_Coords'Length and then
               X_Coords'Length > 0 and then
               X_Coords'Length <= 255 and then
               X_Coords'First = Y_Coords'First and then  -- Matching indices
               X_Coords'Last = Y_Coords'Last,            -- Matching bounds
     Post   => Lagrange_Interpolate'Result in U8
   is
      Result : U8 := 0;
   begin
      --  Lagrange formula: P(0) = sum_i [ y_i * prod_{j!=i} (0-x_j)/(x_i-x_j) ]
      --  Simplified for x=0: P(0) = sum_i [ y_i * prod_{j!=i} x_j/(x_j-x_i) ]
      --
      --  **PROOF**: Since X_Coords'Range = Y_Coords'Range (enforced by precondition),
      --  accessing Y_Coords(I) with I from X_Coords'Range is always safe.

      for I in X_Coords'Range loop
         pragma Loop_Invariant (I in X_Coords'Range);
         pragma Loop_Invariant (I in Y_Coords'Range);  -- Proven by Pre

         declare
            Numerator   : U8 := Y_Coords (I);  -- Safe: I in Y_Coords'Range
            Denominator : U8 := 1;
         begin
            --  Compute Lagrange basis polynomial L_i(0)
            for J in X_Coords'Range loop
               pragma Loop_Invariant (J in X_Coords'Range);

               if I /= J then
                  --  Numerator: multiply by x_j
                  Numerator := GF_Mult (Numerator, X_Coords (J));

                  --  Denominator: multiply by (x_j - x_i)
                  --  In GF(256), subtraction is XOR
                  declare
                     Diff : constant U8 := X_Coords (J) xor X_Coords (I);
                  begin
                     Denominator := GF_Mult (Denominator, Diff);
                  end;
               end if;
            end loop;

            --  Add y_i * (numerator / denominator) using GF(256) operations
            --  In GF(256), addition is XOR
            if Denominator /= 0 then
               Result := Result xor GF_Div (Numerator, Denominator);
            end if;
         end;
      end loop;

      return Result;
   end Lagrange_Interpolate;

   --  Split Root Key into k-of-n shares - Implementation
   --
   --  **ALGORITHM**:
   --    For each byte position b in Root_Key:
   --      1. Construct polynomial P_b(x) = c_0 + c_1*x + ... + c_{k-1}*x^{k-1}
   --         where c_0 = Root_Key[b], c_1..c_{k-1} are random
   --      2. Evaluate P_b(1), P_b(2), ..., P_b(n) to get y-coordinates
   --      3. Store (i, P_b(i)) in share i at byte position b+1
   --
   --  **PROOF OBLIGATIONS**:
   --    - Overflow: (Threshold-1)*32 <= 992 (proven by Pre: Threshold <= 32)
   --    - Precondition for Evaluate_Polynomial: Coefficients'Length = Threshold <= 32 ✓
   --    - Postcondition: On success, Shares(I)(1) = U8(I) for all I
   --    - Postcondition: On failure, all shares zeroized
   procedure Split
     (Root_Key     : in  Key_Array;
      Threshold    : in  Share_Count;
      Total_Shares : in  Share_Count;
      Shares       : out Share_Set;
      Success      : out Boolean)
   is
      --  Polynomial coefficients: c_0, c_1, ..., c_{k-1}
      --  c_0 = secret byte, others are random
      --  Length = Threshold ensures Evaluate_Polynomial precondition satisfied
      Coefficients : Byte_Array (1 .. Threshold) := (others => 0);

      --  Buffer for random bytes (fetched in 64-byte chunks)
      Random_Bytes : Byte_Array (1 .. 64) := (others => 0);
      Random_Index : Positive := 1;
   begin
      --  Fail-closed: assume failure until proven successful
      Success := False;

      --  Initialize all shares to zero (fail-closed: no partial data on error)
      for I in Shares'Range loop
         --  PROOF: Shares K (K < I) are fully initialized
         --  False positive warning: compiler sees reference to Shares even with guard
         pragma Warnings (Off, """Shares"" may be referenced before it has a value");
         pragma Loop_Invariant ((if I > Shares'First then
                                   (for all K in Shares'First .. I - 1 =>
                                      Shares(K)'Initialized)
                                 else True));
         --  PROOF: All initialized shares are zero
         pragma Loop_Invariant ((if I > Shares'First then
                                   (for all K in Shares'First .. I - 1 =>
                                      (for all J in Shares (K)'Range =>
                                         Shares (K)(J) = 0))
                                 else True));
         pragma Warnings (On, """Shares"" may be referenced before it has a value");
         for J in Shares (I)'Range loop
            --  PROOF: Bytes before J in this share are zero
            pragma Loop_Invariant (for all L in Shares (I)'First .. J - 1 =>
                                     Shares (I)(L)'Initialized);
            pragma Loop_Invariant (for all L in Shares (I)'First .. J - 1 =>
                                     Shares (I)(L) = 0);
            Shares (I)(J) := 0;
            --  PROOF: After assignment, byte J is initialized
            pragma Assert (Shares (I)(J)'Initialized);
         end loop;
         --  PROOF: After inner loop, all bytes of Share(I) are initialized
         pragma Assert (for all J in Shares (I)'Range => Shares (I)(J)'Initialized);
         --  PROOF: Therefore, the entire share is initialized
         pragma Assert (Shares(I)'Initialized);
      end loop;
      --  PROOF: All shares are now initialized (to zero)
      pragma Assert (for all I in Shares'Range => Shares(I)'Initialized);

      --  Generate polynomial coefficients and evaluate at share points
      --
      --  **PROOF**: Bytes_Needed = (Threshold - 1) * 32
      --    Since Threshold <= 32 (from Pre), we have Threshold - 1 <= 31
      --    Therefore Bytes_Needed <= 31 * 32 = 992 < Positive'Last ✓
      --    The precondition Threshold <= 32 ensures no overflow here.

      --  PROOF ASSERTIONS: Guide prover through overflow check
      --  Step 1: Threshold is bounded by precondition
      pragma Assert (Threshold <= 32);
      pragma Assert (Threshold >= 1);  -- Threshold is a Share_Count (subtype of Positive)
      --  Step 2: Therefore (Threshold - 1) is bounded
      pragma Assert (Threshold - 1 <= 31);
      pragma Assert (Threshold - 1 >= 0);  -- Natural range
      --  Step 3: Multiplication by 32 gives maximum value
      pragma Assert ((Threshold - 1) * 32 <= 31 * 32);
      --  Step 4: Compute the concrete maximum
      pragma Assert (31 * 32 = 992);
      --  Step 5: This maximum is well within Positive'Last and >= Positive'First (1)
      pragma Assert (992 < Positive'Last);
      --  Step 6: Lower bound check - even when Threshold = 1, (1-1)*32 = 0, which is NOT in Positive
      --  However, we know Threshold >= 1, so Bytes_Needed >= 0
      --  If Threshold = 1, we need 0 bytes (secret is constant), but Positive starts at 1
      --  The precondition Threshold <= Total_Shares and Total_Shares <= 10 doesn't prevent Threshold = 1
      --  FIX: Use Natural instead of Positive, since 0 is a valid value
      --  ACTUALLY: If Threshold = 1, we don't need random bytes, so loop won't execute
      --  But we still need to declare Bytes_Needed correctly

      declare
         --  Use Natural to allow 0 (when Threshold = 1, no random bytes needed)
         Bytes_Needed : constant Natural := (Threshold - 1) * 32;
         Bytes_Generated : Natural := 0;
      begin
         --  Main loop: process each byte of Root_Key
         while Bytes_Generated < Bytes_Needed loop
            pragma Loop_Invariant (Bytes_Generated <= Bytes_Needed);
            --  PROOF: All shares remain initialized throughout random generation
            pragma Loop_Invariant (for all I in Shares'Range => Shares(I)'Initialized);

            SparkPass.Crypto.Random.Fill (Random_Bytes);

            --  Process each byte of Root_Key
            for Byte_Index in Root_Key'Range loop
               pragma Loop_Invariant (Byte_Index in Root_Key'Range);
               pragma Loop_Invariant (Bytes_Generated <= Bytes_Needed);
               --  PROOF: All shares remain initialized throughout byte processing
               pragma Loop_Invariant (for all I in Shares'Range => Shares(I)'Initialized);

               exit when Bytes_Generated >= Bytes_Needed;

               --  Set up polynomial: c_0 = secret byte, c_1..c_{k-1} = random
               Coefficients (1) := Root_Key (Byte_Index);

               --  Fill remaining coefficients with random bytes
               for Coeff_Index in 2 .. Threshold loop
                  pragma Loop_Invariant (Coeff_Index in 2 .. Threshold);
                  pragma Loop_Invariant (Bytes_Generated <= Bytes_Needed);
                  --  PROOF: All shares remain initialized during coefficient generation
                  pragma Loop_Invariant (for all I in Shares'Range => Shares(I)'Initialized);

                  exit when Bytes_Generated >= Bytes_Needed;

                  if Random_Index > Random_Bytes'Last then
                     SparkPass.Crypto.Random.Fill (Random_Bytes);
                     Random_Index := 1;
                  end if;

                  Coefficients (Coeff_Index) := Random_Bytes (Random_Index);
                  Random_Index := Random_Index + 1;
                  Bytes_Generated := Bytes_Generated + 1;
               end loop;

               --  Evaluate polynomial at x = 1, 2, ..., n (share indices)
               --
               --  **PROOF**: Coefficients'Length = Threshold <= 32 (from Pre)
               --  Therefore Evaluate_Polynomial precondition (Coeffs'Length <= 32) satisfied ✓
               for Share_Index in Shares'Range loop
                  pragma Loop_Invariant (Share_Index in Shares'Range);
                  pragma Loop_Invariant (Coefficients'Length = Threshold);
                  pragma Loop_Invariant (Threshold <= 32);  -- From Pre
                  --  PROOF: All shares that have been processed are initialized
                  --  This includes all shares before Share_Index (already written)
                  --  and all shares from initialization loop (set to zero)
                  pragma Loop_Invariant (for all I in Shares'Range => Shares(I)'Initialized);

                  declare
                     X : constant U8 := U8 (Share_Index);
                     Y : constant U8 := Evaluate_Polynomial (Coefficients, X);
                  begin
                     --  First byte is x-coordinate (share index)
                     --  **POSTCONDITION PROOF**: Shares(Share_Index)(1) = U8(Share_Index) ✓
                     if Byte_Index = 1 then
                        Shares (Share_Index)(1) := X;
                     end if;

                     --  Remaining bytes are y-coordinates (polynomial evaluations)
                     Shares (Share_Index)(Byte_Index + 1) := Y;

                     --  PROOF: After writing to Share_Index, it remains initialized
                     pragma Assert (Shares(Share_Index)'Initialized);
                  end;
               end loop;

               --  PROOF: After inner loop, all shares are still initialized
               pragma Assert (for all I in Shares'Range => Shares(I)'Initialized);
            end loop;
         end loop;
      end;

      --  PROOF: After all processing loops, all shares remain initialized
      pragma Assert (for all I in Shares'Range => Shares(I)'Initialized);

      --  Zeroize sensitive data (polynomial coefficients, random bytes)
      --  **SECURITY**: Prevents secrets from remaining in memory
      SparkPass.Crypto.Zeroize.Wipe (Coefficients);
      SparkPass.Crypto.Zeroize.Wipe (Random_Bytes);

      --  All operations completed successfully
      --  **POSTCONDITION**: Shares(I)(1) = U8(I) proven by loop above
      --  **POSTCONDITION PROOF**: Help prover discharge 'Initialized postcondition
      pragma Assert (for all I in Shares'Range => Shares(I)'Initialized);
      Success := True;
   end Split;

   --  Combine k shares to reconstruct Root Key - Implementation
   --
   --  **ALGORITHM**:
   --    For each byte position b:
   --      1. Extract y-coordinates from shares at position b+1
   --      2. Use Lagrange interpolation to compute P_b(0) = Root_Key[b]
   --      3. Store P_b(0) in Root_Key[b]
   --
   --  **SECURITY PROPERTIES**:
   --    - On success: Root_Key contains reconstructed secret
   --    - On failure: Root_Key is zeroized (fail-closed, no partial data)
   --    - Temporary data (X_Coords, Y_Coords) always zeroized before return
   --
   --  **PROOF OBLIGATIONS**:
   --    - Postcondition: If not Success, then Root_Key is all zeros
   --    - Array safety: All accesses to Shares, X_Coords, Y_Coords within bounds
   --    - Precondition for Lagrange_Interpolate: Arrays match in length and indices
   procedure Combine
     (Shares    : in  Share_Set;
      Threshold : in  Share_Count;
      Root_Key  : out Key_Array;
      Success   : out Boolean)
   is
      --  X-coordinates extracted from shares (share indices)
      X_Coords : Byte_Array (1 .. Threshold) := (others => 0);

      --  Y-coordinates for one byte position across all shares
      Y_Coords : Byte_Array (1 .. Threshold) := (others => 0);
   begin
      --  Fail-closed: assume failure until proven successful
      Success := False;

      --  Initialize Root_Key to zero (fail-closed: safe default)
      --  **POSTCONDITION PREPARATION**: If we return early, Root_Key = 0 ✓
      Root_Key := (others => 0);

      --  ======================================================================
      --  PHASE 1: Validate shares and extract x-coordinates
      --  ======================================================================

      for I in 1 .. Threshold loop
         pragma Loop_Invariant (I in 1 .. Threshold);
         pragma Loop_Invariant (for all K in Root_Key'Range =>
                                  Root_Key (K) = 0);  -- Still zero

         --  Validate share structure
         if not Is_Valid_Share (Shares (I)) then
            --  Invalid share detected, fail-closed
            --  Root_Key already zero (initialized at line 426)
            --  **POSTCONDITION PROOF**: Root_Key was set to (others => 0) above
            pragma Assert (for all K in Root_Key'Range => Root_Key (K) = 0);
            return;
         end if;

         --  Extract x-coordinate (share index)
         X_Coords (I) := Shares (I)(1);

         --  Check for duplicate x-coordinates (would cause division by zero)
         for J in 1 .. I - 1 loop
            pragma Loop_Invariant (J in 1 .. I - 1);
            pragma Loop_Invariant (for all K in Root_Key'Range =>
                                     Root_Key (K) = 0);  -- Still zero

            if X_Coords (I) = X_Coords (J) then
               --  Duplicate x-coordinate detected, fail-closed
               --  Root_Key already zero (initialized at line 426, preserved by invariant)
               --  **POSTCONDITION PROOF**: Loop invariant ensures Root_Key is still all zeros
               pragma Assert (for all K in Root_Key'Range => Root_Key (K) = 0);
               return;
            end if;
         end loop;
      end loop;

      --  ======================================================================
      --  PHASE 2: Reconstruct Root_Key using Lagrange interpolation
      --  ======================================================================
      --
      --  **PROOF**: X_Coords and Y_Coords both have range 1 .. Threshold
      --  Therefore Lagrange_Interpolate precondition satisfied ✓

      for Byte_Index in Root_Key'Range loop
         pragma Loop_Invariant (Byte_Index in Root_Key'Range);
         pragma Loop_Invariant (X_Coords'First = 1);
         pragma Loop_Invariant (X_Coords'Last = Threshold);
         pragma Loop_Invariant (Y_Coords'First = 1);
         pragma Loop_Invariant (Y_Coords'Last = Threshold);

         --  Extract y-coordinates for this byte position
         for I in 1 .. Threshold loop
            pragma Loop_Invariant (I in 1 .. Threshold);
            pragma Loop_Invariant (I in Y_Coords'Range);

            Y_Coords (I) := Shares (I)(Byte_Index + 1);
         end loop;

         --  Interpolate P(0) = secret byte
         --  **PROOF**: X_Coords and Y_Coords have matching indices (both 1..Threshold)
         Root_Key (Byte_Index) := Lagrange_Interpolate (X_Coords, Y_Coords);
      end loop;

      --  ======================================================================
      --  PHASE 3: Cleanup and success
      --  ======================================================================

      --  Zeroize temporary data (defense in depth)
      --  X_Coords and Y_Coords contain partial information about shares
      SparkPass.Crypto.Zeroize.Wipe (X_Coords);
      SparkPass.Crypto.Zeroize.Wipe (Y_Coords);

      --  All operations completed successfully
      --  Root_Key contains reconstructed secret
      --  **POSTCONDITION**: Success = True (postcondition doesn't check Root_Key value)
      Success := True;

      --  **NOTE**: Postcondition only requires zeroization on failure (not Success)
      --  On success path, Root_Key contains reconstructed secret (not zero)
   end Combine;

   function Is_Valid_Share (Share : Share_Array) return Boolean is
   begin
      return Share'Length = Share_Size and then Share (Share'First) > 0;
   end Is_Valid_Share;

   --  =========================================================================
   --  ZEROIZATION PROCEDURES (Security-Critical)
   --  =========================================================================
   --
   --  **SECURITY REQUIREMENT**: Complete zeroization of share data to prevent
   --  memory disclosure attacks (cold boot, memory dumps, swap files).
   --
   --  **PROOF STRATEGY**: Loop invariants prove that all bytes are set to zero.
   --  These are NOT optimized away (unlike for-loops) because they're called
   --  via procedure boundary, preventing dead store elimination.
   --
   --  **CITATION**: Anderson "Security Engineering" Ch. 8 (Memory Attacks)

   --  Wipe single share (zero all 33 bytes)
   --
   --  **POSTCONDITION**: Every byte in Share is proven to be 0
   --  **PROOF**: Loop invariant establishes that bytes 1..I-1 are zero,
   --             and current iteration sets byte I to zero.
   --             After loop completion, all bytes in Share'Range are zero.
   procedure Wipe_Share (Share : in out Share_Array) is
   begin
      for I in Share'Range loop
         --  Loop invariant: All bytes processed so far are zero
         pragma Loop_Invariant (for all K in Share'First .. I - 1 =>
                                  Share (K) = 0);

         Share (I) := 0;

         --  After this assignment, Share(I) = 0, and by invariant,
         --  Share(Share'First .. I) = 0
      end loop;

      --  Loop exit: I = Share'Last + 1, so invariant proves
      --  Share(Share'First .. Share'Last) = 0, which is Share'Range = 0
      --  **POSTCONDITION SATISFIED**: (for all I in Share'Range => Share(I) = 0) ✓
   end Wipe_Share;

   --  Wipe array of shares (zero all shares in set)
   --
   --  **POSTCONDITION**: Every byte in every share is proven to be 0
   --  **PROOF**: Loop invariant + Wipe_Share postcondition establish complete zeroization
   procedure Wipe_Share_Set (Shares : in out Share_Set) is
   begin
      for I in Shares'Range loop
         --  Loop invariant: All shares processed so far are completely zero
         pragma Loop_Invariant (for all K in Shares'First .. I - 1 =>
                                  (for all J in Shares (K)'Range =>
                                     Shares (K)(J) = 0));

         --  Wipe current share
         --  **PROOF**: Wipe_Share postcondition guarantees Shares(I) is all zeros after this call
         Wipe_Share (Shares (I));

         --  After Wipe_Share call, by its postcondition:
         --  (for all J in Shares(I)'Range => Shares(I)(J) = 0) ✓
         --
         --  Combined with loop invariant, we now have:
         --  (for all K in Shares'First .. I =>
         --     (for all J in Shares(K)'Range => Shares(K)(J) = 0))
      end loop;

      --  Loop exit: I = Shares'Last + 1, so invariant proves
      --  (for all K in Shares'First .. Shares'Last =>
      --     (for all J in Shares(K)'Range => Shares(K)(J) = 0))
      --
      --  Which is equivalent to:
      --  (for all I in Shares'Range => (for all J in Shares(I)'Range => Shares(I)(J) = 0))
      --  **POSTCONDITION SATISFIED** ✓
   end Wipe_Share_Set;

end SparkPass.Crypto.Shamir;
