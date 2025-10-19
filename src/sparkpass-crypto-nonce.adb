pragma SPARK_Mode (On);
with Interfaces; use type Interfaces.Unsigned_64;
with SparkPass.Crypto.HKDF;

--  ============================================================================
--  SPARKPASS DETERMINISTIC NONCE DERIVATION IMPLEMENTATION
--  ============================================================================
--
--  This implementation uses HKDF-SHA-384 to derive nonces from structured
--  input consisting of:
--    1. Counter (8 bytes, big-endian U64)
--    2. Entry_ID (16 bytes, UUIDv4)
--    3. Domain separator (10-20 bytes, ASCII string)
--
--  **MEMORY SAFETY**: All operations are stack-allocated, no heap, no pointers.
--  **TIMING SAFETY**: Not required (nonce derivation is public operation).
--  **SPARK VERIFICATION**: All array accesses proven safe at compile time.
--
--  ============================================================================

package body SparkPass.Crypto.Nonce is

   --  HKDF salt for nonce derivation (version 1)
   --  This salt is fixed and public (not secret). It provides domain
   --  separation between nonce derivation and other HKDF uses in SparkPass
   --  (e.g., key derivation, key wrapping).
   --
   --  **Why "SparkPass.Nonce.v1"?**
   --  - "SparkPass": Application-specific namespace
   --  - "Nonce": Operation-specific context
   --  - "v1": Version identifier (allows future algorithm changes)
   --
   --  Length: 18 bytes (sufficient for HKDF, per RFC 5869 recommendation)
   Nonce_Salt : constant Byte_Array (1 .. 18) :=
     (16#53#, 16#70#, 16#61#, 16#72#, 16#6B#,  --  "Spark"
      16#50#, 16#61#, 16#73#, 16#73#,          --  "Pass"
      16#2E#,                                    --  "."
      16#4E#, 16#6F#, 16#6E#, 16#63#, 16#65#,  --  "Nonce"
      16#2E#,                                    --  "."
      16#76#, 16#31#);                          --  "v1"

   --  =========================================================================
   --  DOMAIN SEPARATOR CONVERSION
   --  =========================================================================

   function Domain_To_Bytes (Domain : Domain_Separator) return Byte_Array is
   begin
      case Domain is
         when Entry_Data =>
            --  "entry.data" (10 bytes)
            return (16#65#, 16#6E#, 16#74#, 16#72#, 16#79#,  --  "entry"
                    16#2E#,                                    --  "."
                    16#64#, 16#61#, 16#74#, 16#61#);          --  "data"

         when Entry_Metadata =>
            --  "entry.metadata" (14 bytes)
            return (16#65#, 16#6E#, 16#74#, 16#72#, 16#79#,  --  "entry"
                    16#2E#,                                    --  "."
                    16#6D#, 16#65#, 16#74#, 16#61#,           --  "meta"
                    16#64#, 16#61#, 16#74#, 16#61#);          --  "data"

         when Header_Seal =>
            --  "header.seal" (11 bytes)
            return (16#68#, 16#65#, 16#61#, 16#64#, 16#65#, 16#72#,  --  "header"
                    16#2E#,                                           --  "."
                    16#73#, 16#65#, 16#61#, 16#6C#);                 --  "seal"

         when Log_Record =>
            --  "log.record" (10 bytes)
            return (16#6C#, 16#6F#, 16#67#,           --  "log"
                    16#2E#,                            --  "."
                    16#72#, 16#65#, 16#63#,           --  "rec"
                    16#6F#, 16#72#, 16#64#);          --  "ord"
      end case;
   end Domain_To_Bytes;

   --  =========================================================================
   --  NONCE DERIVATION IMPLEMENTATION
   --  =========================================================================

   function Derive_Nonce
     (Counter  : in U64;
      Entry_ID : in Entry_Id_Array;
      Domain   : in Domain_Separator)
     return Nonce_Array
   is
      --  Convert counter to big-endian byte array (8 bytes)
      --  Big-endian ensures lexicographic ordering matches numeric ordering
      --  (counter=1 < counter=2 in both representations)
      --
      --  PLATINUM PROOF: This encoding is identical to Counter_To_Bytes_Ghost
      --  and therefore inherits its injectivity property.
      Counter_Bytes : constant Byte_Array (1 .. 8) :=
        (1 => U8 (Interfaces.Shift_Right (Counter, 56) and 16#FF#),
         2 => U8 (Interfaces.Shift_Right (Counter, 48) and 16#FF#),
         3 => U8 (Interfaces.Shift_Right (Counter, 40) and 16#FF#),
         4 => U8 (Interfaces.Shift_Right (Counter, 32) and 16#FF#),
         5 => U8 (Interfaces.Shift_Right (Counter, 24) and 16#FF#),
         6 => U8 (Interfaces.Shift_Right (Counter, 16) and 16#FF#),
         7 => U8 (Interfaces.Shift_Right (Counter, 8) and 16#FF#),
         8 => U8 (Counter and 16#FF#));

      --  PLATINUM ASSERTION: Prove equivalence to ghost function
      pragma Assert (Counter_Bytes = Counter_To_Bytes_Ghost (Counter));

      --  Get domain separator as byte array
      Domain_Bytes : constant Byte_Array := Domain_To_Bytes (Domain);

      --  Construct HKDF input keying material (IKM):
      --  IKM = Counter (8) || Entry_ID (16) || Domain (10..20)
      --  Maximum length: 8 + 16 + 20 = 44 bytes
      --
      --  **PROOF STRATEGY**: IKM is initialized piecewise in three loops below:
      --    1. Bytes 1-8: Counter (loop over Counter_Bytes)
      --    2. Bytes 9-24: Entry_ID (loop over Entry_ID)
      --    3. Bytes 25-44: Domain (loop over Domain_Bytes)
      --
      --  Relaxed_Initialization tells SPARK to check initialization at use site
      --  (HKDF.Derive call) rather than declaration. This allows piecewise init.
      IKM_Length : constant Positive := 8 + Entry_Id_Size + Domain_Bytes'Length;
      IKM        : Byte_Array (1 .. IKM_Length)
        with Relaxed_Initialization;

      --  HKDF info parameter (empty for nonce derivation)
      --  We encode all context in IKM and Salt, following RFC 5869 guidance
      Empty_Info : constant Byte_Array (1 .. 0) := (others => 0);

      --  Derived nonce (12 bytes for AES-GCM-SIV)
      Result : Nonce_Array;

   begin
      --  ======================================================================
      --  STEP 1: Construct IKM by concatenating Counter, Entry_ID, Domain
      --  ======================================================================
      --
      --  Memory layout (example for Entry_Data):
      --  Offset  Length  Content
      --  ------  ------  -------
      --  1-8     8       Counter (big-endian U64)
      --  9-24    16      Entry_ID (UUIDv4 bytes)
      --  25-34   10      Domain ("entry.data")
      --
      --  This construction is injective because:
      --  1. Fixed-length fields (Counter, Entry_ID) prevent prefix ambiguity
      --  2. Variable-length field (Domain) is last, no parsing ambiguity
      --  3. Domain values are disjoint (no two domains produce same bytes)

      --  Copy Counter bytes (offset 1-8)
      for I in Counter_Bytes'Range loop
         pragma Loop_Invariant (I in Counter_Bytes'Range);
         pragma Loop_Invariant (I in IKM'Range);
         --  PROOF: Bytes 1..I-1 initialized in previous iterations
         pragma Loop_Invariant (for all K in 1 .. I - 1 => IKM(K)'Initialized);
         IKM (I) := Counter_Bytes (I);
      end loop;

      --  Copy Entry_ID bytes (offset 9-24)
      for I in Entry_ID'Range loop
         pragma Loop_Invariant (I in Entry_ID'Range);
         pragma Loop_Invariant (I in 1 .. Entry_Id_Size);
         pragma Loop_Invariant (8 + I in IKM'Range);
         --  PROOF: Bytes 1..8 initialized from Counter loop
         pragma Loop_Invariant (for all K in 1 .. 8 => IKM(K)'Initialized);
         --  PROOF: Bytes 9..8+I-1 initialized in previous iterations
         pragma Loop_Invariant (for all K in 9 .. 8 + I - 1 => IKM(K)'Initialized);
         IKM (8 + I) := Entry_ID (I);
      end loop;

      --  Copy Domain bytes (offset 25-44)
      for I in Domain_Bytes'Range loop
         pragma Loop_Invariant (I in Domain_Bytes'Range);
         pragma Loop_Invariant (I >= 1);
         pragma Loop_Invariant (24 + I in IKM'Range);
         --  PROOF: Bytes 1..24 initialized from Counter+Entry_ID loops
         pragma Loop_Invariant (for all K in 1 .. 24 => IKM(K)'Initialized);
         --  PROOF: Bytes 25..24+I-1 initialized in previous iterations
         pragma Loop_Invariant (for all K in 25 .. 24 + I - 1 => IKM(K)'Initialized);
         IKM (24 + I) := Domain_Bytes (I);
      end loop;

      --  ======================================================================
      --  STEP 2: Derive nonce using HKDF-SHA-384
      --  ======================================================================
      --
      --  HKDF parameters:
      --  - IKM: Constructed above (Counter || Entry_ID || Domain)
      --  - Salt: "SparkPass.Nonce.v1" (18 bytes, constant)
      --  - Info: Empty (all context in IKM)
      --  - Length: 12 bytes (AES-GCM-SIV nonce size)
      --
      --  Security analysis:
      --  - HKDF-SHA-384 is a PRF (Katz & Lindell, Theorem 6.3)
      --  - 12-byte output from 48-byte hash provides negligible collision
      --    probability (< 2⁻⁹⁶ by birthday paradox)
      --  - Combined with 128-bit Entry_ID uniqueness, total collision
      --    probability < 2⁻²²⁴ (astronomically negligible)

      --  PROOF: All IKM bytes are now fully initialized
      --  Relaxed_Initialization requires explicit proof before use
      pragma Assert (for all K in IKM'Range => IKM(K)'Initialized);

      declare
         HKDF_Output : constant Byte_Array :=
           SparkPass.Crypto.HKDF.Derive
             (IKM    => IKM,
              Salt   => Nonce_Salt,
              Info   => Empty_Info,
              Length => 12);
      begin
         --  Copy HKDF output to result nonce
         for I in Result'Range loop
            pragma Loop_Invariant (I in Result'Range);
            pragma Loop_Invariant (I in HKDF_Output'Range);
            Result (I) := HKDF_Output (I);
         end loop;
      end;

      --  ======================================================================
      --  STEP 3: Return derived nonce
      --  ======================================================================
      --
      --  Post-condition verified by SPARK:
      --  - Result'Length = 12
      --  - Result'First = 1
      --  - Result'Last = 12
      --
      --  No zeroization required: IKM contains only public metadata
      --  (counter, entry ID, domain separator), no secret key material.

      return Result;

   end Derive_Nonce;

end SparkPass.Crypto.Nonce;
