pragma SPARK_Mode (On);
with Interfaces;

package body SparkPass.Crypto.Zeroize is
   use type Interfaces.Unsigned_8;

   --  Runtime check version - iterates to verify all bytes are zero
   function Is_Zeroed (Buffer : Byte_Array) return Boolean is
   begin
      for I in Buffer'Range loop
         pragma Loop_Invariant (for all J in Buffer'First .. I - 1 =>
            (Buffer (J) = 0));

         if Buffer (I) /= 0 then
            return False;
         end if;
      end loop;
      return True;
   end Is_Zeroed;

   procedure Wipe (Buffer : in out Byte_Array) is
   begin
      --  Handle empty arrays
      if Buffer'Length = 0 then
         pragma Assert (Is_Zeroed_Ghost (Buffer));
         return;
      end if;

      --  Zero each byte in sequence
      for I in Buffer'Range loop
         pragma Loop_Invariant (I in Buffer'Range);
         pragma Loop_Invariant (for all J in Buffer'First .. I - 1 =>
            Buffer (J) = 0);

         Buffer (I) := 0;

         pragma Assert (Buffer (I) = 0);
         pragma Assert (for all J in Buffer'First .. I => Buffer (J) = 0);
      end loop;

      --  After loop: all elements have been zeroed
      pragma Assert (for all K in Buffer'Range => Buffer (K) = 0);
      pragma Assert (Is_Zeroed_Ghost (Buffer));
   end Wipe;

   procedure Wipe_Key (Buffer : in out Key_Array) is
   begin
      --  Key_Array is a subtype of Byte_Array, so we can iterate directly
      for I in Buffer'Range loop
         pragma Loop_Invariant (I in Buffer'Range);
         pragma Loop_Invariant (for all J in Buffer'First .. I - 1 =>
            Buffer (J) = 0);

         Buffer (I) := 0;
      end loop;

      pragma Assert (for all K in Buffer'Range => Buffer (K) = 0);
      pragma Assert (Is_Zeroed_Ghost (Byte_Array (Buffer)));
   end Wipe_Key;

   procedure Wipe_Tag (Buffer : in out Tag_Array) is
   begin
      --  Tag_Array is a subtype of Byte_Array, so we can iterate directly
      for I in Buffer'Range loop
         pragma Loop_Invariant (I in Buffer'Range);
         pragma Loop_Invariant (for all J in Buffer'First .. I - 1 =>
            Buffer (J) = 0);

         Buffer (I) := 0;
      end loop;

      pragma Assert (for all K in Buffer'Range => Buffer (K) = 0);
      pragma Assert (Is_Zeroed_Ghost (Byte_Array (Buffer)));
   end Wipe_Tag;

   procedure Wipe_Chain (Buffer : in out Chain_Key_Array) is
   begin
      --  Chain_Key_Array is a subtype of Byte_Array, so we can iterate directly
      for I in Buffer'Range loop
         pragma Loop_Invariant (I in Buffer'Range);
         pragma Loop_Invariant (for all J in Buffer'First .. I - 1 =>
            Buffer (J) = 0);

         Buffer (I) := 0;
      end loop;

      pragma Assert (for all K in Buffer'Range => Buffer (K) = 0);
      pragma Assert (Is_Zeroed_Ghost (Byte_Array (Buffer)));
   end Wipe_Chain;

   --  PLATINUM NOTE: Equal implements constant-time comparison using XOR accumulation.
   --  This is implemented in pure SPARK for provability. The algorithm ensures:
   --  1. No early exit - always processes all bytes
   --  2. Result computed by ORing XOR of all byte pairs
   --  3. Returns True iff all bytes match (Result = 0)
   function Equal (Left : Byte_Array; Right : Byte_Array) return Boolean is
      Result : U8 := 0;
   begin
      --  Pure SPARK constant-time comparison using XOR accumulation
      --  No early exit - always processes all bytes
      for I in Left'Range loop
         pragma Loop_Invariant (I in Left'Range);
         pragma Loop_Invariant (I - Left'First + Right'First in Right'Range);
         pragma Loop_Invariant ((Result = 0) = (for all J in Left'First .. I - 1 =>
            Left (J) = Right (J - Left'First + Right'First)));

         --  Accumulate XOR of differences
         --  Result stays 0 only if all bytes match
         Result := Result or (Left (I) xor Right (I - Left'First + Right'First));
      end loop;

      --  Final assertion: Result = 0 iff all bytes matched
      pragma Assert ((Result = 0) = (for all K in Left'Range =>
         Left (K) = Right (K - Left'First + Right'First)));

      return Result = 0;
   end Equal;

end SparkPass.Crypto.Zeroize;
