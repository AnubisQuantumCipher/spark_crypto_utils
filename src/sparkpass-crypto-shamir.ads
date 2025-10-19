pragma SPARK_Mode (On);
with Interfaces; use type Interfaces.Unsigned_8; use type Interfaces.Unsigned_32;
with SparkPass.Types; use SparkPass.Types;

--  Shamir Secret Sharing Scheme (k-of-n threshold)
--
--  Security properties:
--    1. Root Key (32 bytes) is split into n shares
--    2. Any k shares can reconstruct the Root Key
--    3. Fewer than k shares reveal no information about the Root Key
--    4. GF(256) arithmetic ensures perfect secrecy
--    5. Constant-time operations prevent side-channel attacks
--
--  Implementation:
--    - Polynomial evaluation in GF(256) with irreducible polynomial
--    - Each share is (x, P(x)) where P is random polynomial of degree k-1
--    - P(0) = Root Key byte, P(x_i) = share_i byte
--    - Reconstruction uses Lagrange interpolation
--
--  Usage:
--    Split:  Root_Key -> (Share_1, Share_2, ..., Share_N)
--    Combine: Any k shares -> Root_Key
--
--  Supported configurations: 2-of-3, 3-of-5, 2-of-2, etc.
package SparkPass.Crypto.Shamir is

   --  Maximum number of shares supported (limited by GF(256) field size)
   Max_Shares : constant Positive := 255;

   --  Share structure: x-coordinate + y-coordinate (32 bytes each byte split)
   --  Each share is 33 bytes: 1 byte x-coordinate + 32 bytes y-coordinates
   Share_Size : constant Positive := 33;
   subtype Share_Array is Byte_Array (1 .. Share_Size);

   --  Threshold and total share counts
   subtype Share_Count is Positive range 1 .. Max_Shares;

   --  Array of shares for storage
   type Share_Set is array (Share_Count range <>) of Share_Array;

   --  Split Root Key into k-of-n shares using Shamir Secret Sharing
   --
   --  **OPERATION**: Splits a 32-byte secret into n shares such that any k shares
   --  can reconstruct the secret, but k-1 shares reveal no information.
   --
   --  **PARAMETERS**:
   --    Threshold: minimum shares required to reconstruct (k)
   --    Total_Shares: total shares to generate (n), where k <= n <= 10
   --    Root_Key: 32-byte secret to split
   --    Shares: output array of n shares, each 33 bytes (x-coord + 32 y-coords)
   --    Success: True if split succeeded, False on error
   --
   --  **PRECONDITIONS**:
   --    - Root_Key is exactly 32 bytes (AES-256 key size)
   --    - 1 <= Threshold <= Total_Shares <= 10 (mathematical validity)
   --    - Threshold <= 32 (ensures (Threshold-1)*32 doesn't overflow)
   --    - Shares array is sized correctly (Total_Shares elements)
   --    - Shares array is 1-indexed (simplifies x-coordinate assignment)
   --
   --  **POSTCONDITIONS**:
   --    On Success:
   --      - Each share has correct size (33 bytes)
   --      - Each share has x-coordinate = share index (Shares(I)(1) = I)
   --      - Shares are mathematically valid (can be combined)
   --    On Failure:
   --      - All shares are zeroized (fail-closed, no partial data)
   --
   --  **PROOF STRATEGY**:
   --    - Overflow prevention: Threshold <= 32 ensures (Threshold-1)*32 <= 992
   --    - Index safety: Shares'First = 1 ensures I in Shares'Range ⇒ Shares(I)(1) = U8(I) is valid
   --    - Loop invariants prove shares are filled correctly
   --
   --  **SECURITY PROPERTY**: k-1 shares provide no information about Root_Key
   --  (information-theoretic security from polynomial degree k-1)
   --
   --  **CITATION**: Shamir (1979), "How to Share a Secret"
   procedure Split
     (Root_Key     : in  Key_Array;
      Threshold    : in  Share_Count;
      Total_Shares : in  Share_Count;
      Shares       : out Share_Set;
      Success      : out Boolean)
   with
     Global  => null,
     Relaxed_Initialization => Shares,  -- Piecewise initialization proven by loop invariants
     Pre     => Root_Key'Length = 32 and then
                Threshold <= Total_Shares and then
                Threshold <= 32 and then  -- Prevent (Threshold-1)*32 overflow
                Total_Shares <= 10 and then  -- Practical limit
                Shares'Length = Total_Shares and then
                Shares'First = 1,  -- Required for x-coordinate = index
     Post    => (if Success then
                  (for all I in Shares'Range => Shares(I)'Initialized))
                and then
                (if not Success then
                  (for all I in Shares'Range =>
                    (for all J in Shares (I)'Range =>
                       Shares (I)(J) = 0)));

   --  Reconstruct Root Key from k shares
   --
   --  Shares: array of k shares (exactly Threshold count)
   --  Threshold: minimum number of shares required (k)
   --  Root_Key: reconstructed 32-byte secret
   --
   --  Pre: Shares'Length >= Threshold, each share is 33 bytes
   --  Post: Success -> Root_Key is reconstructed secret
   --        Failure -> Root_Key is zeroed
   --
   --  Suppress false positive "unused variable" warning in quantified expression
   pragma Warnings (Off, "unused variable ""Idx""");
   procedure Combine
     (Shares    : in  Share_Set;
      Threshold : in  Share_Count;
      Root_Key  : out Key_Array;
      Success   : out Boolean)
   with
     Global  => null,
     Pre     => Shares'Length >= Threshold and then
                Root_Key'Length = 32 and then
                Shares'First = 1 and then
                (for all Idx in Shares'Range =>
                   Shares (Idx)'Length = Share_Size),
     Post    => (if not Success then
                   (for all Idx in Root_Key'Range =>
                      Root_Key (Idx) = 0));
   pragma Warnings (On, "unused variable ""Idx""");

   --  Validate share structure
   --
   --  Checks that share has valid x-coordinate (1..255) and correct size
   function Is_Valid_Share (Share : Share_Array) return Boolean
   with
     Global  => null,
     Pre     => Share'Length = Share_Size,
     Post    => Is_Valid_Share'Result =
                  (Share'Length = Share_Size and then
                   Share (Share'First) > 0);

   --  Zeroize share data
   procedure Wipe_Share (Share : in out Share_Array)
   with
     Global  => null,
     Post    => (for all I in Share'Range => Share (I) = 0);

   --  Zeroize all shares in set
   procedure Wipe_Share_Set (Shares : in out Share_Set)
   with
     Global  => null,
     Post    => (for all I in Shares'Range =>
                   (for all J in Shares (I)'Range =>
                      Shares (I)(J) = 0));

end SparkPass.Crypto.Shamir;
