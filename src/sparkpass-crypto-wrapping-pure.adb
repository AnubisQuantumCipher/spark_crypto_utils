pragma SPARK_Mode (On);
with SparkPass.Crypto.Zeroize;

package body SparkPass.Crypto.Wrapping.Pure is

   --  -------------------------------------------------------------------------
   --  MARMARAGAN STRATEGY: Assert statements (100% success) + Single loop invariants (64% success)
   --  -------------------------------------------------------------------------

   procedure Serialize_Wrapped_Key_Pure
     (Wrapped : in     Wrapped_Key;
      Buffer  : out    Wrapped_Key_Array;
      Success : out    Boolean)
   is
      Offset : Positive := Buffer'First;
   begin
      Success := False;

      if not Wrapped.Present then
         Buffer := (others => 0);
         return;
      end if;

      --  MARMARAGAN: Assert statements have 100% success rate
      pragma Assert (Buffer'Length = 60);
      pragma Assert (Wrapped.Nonce'Length = 12);
      pragma Assert (Wrapped.Ciphertext'Length = 32);
      pragma Assert (Wrapped.Tag'Length = 16);

      --  Layout: Nonce (12) + Ciphertext (32) + Tag (16) = 60 bytes
      for I in Wrapped.Nonce'Range loop
         Buffer (Offset) := Wrapped.Nonce (I);
         Offset := Offset + 1;
         --  MARMARAGAN: Single loop invariant (64% success rate)
         pragma Loop_Invariant (Offset = Buffer'First + I);
         pragma Loop_Invariant (for all J in 1 .. I =>
           Buffer (Buffer'First + J - 1) = Wrapped.Nonce (J));
      end loop;

      pragma Assert (Offset = Buffer'First + 12);

      for I in Wrapped.Ciphertext'Range loop
         Buffer (Offset) := Wrapped.Ciphertext (I);
         Offset := Offset + 1;
         pragma Loop_Invariant (Offset = Buffer'First + 12 + I);
         pragma Loop_Invariant (for all J in 1 .. I =>
           Buffer (Buffer'First + 12 + J - 1) = Wrapped.Ciphertext (J));
      end loop;

      pragma Assert (Offset = Buffer'First + 44);

      for I in Wrapped.Tag'Range loop
         Buffer (Offset) := Wrapped.Tag (I);
         Offset := Offset + 1;
         pragma Loop_Invariant (Offset = Buffer'First + 44 + I);
         pragma Loop_Invariant (for all J in 1 .. I =>
           Buffer (Buffer'First + 44 + J - 1) = Wrapped.Tag (J));
      end loop;

      pragma Assert (Offset = Buffer'First + 60);

      Success := True;
   end Serialize_Wrapped_Key_Pure;

   procedure Deserialize_Wrapped_Key_Pure
     (Buffer  : in     Wrapped_Key_Array;
      Wrapped : out    Wrapped_Key;
      Success : out    Boolean)
   is
      Offset : Positive := Buffer'First;
   begin
      Wrapped.Present := False;
      Success := False;

      --  MARMARAGAN: Assert statements for preconditions (100% success)
      pragma Assert (Buffer'Length = 60);

      --  Layout: Nonce (12) + Ciphertext (32) + Tag (16) = 60 bytes
      for I in Wrapped.Nonce'Range loop
         Wrapped.Nonce (I) := Buffer (Offset);
         Offset := Offset + 1;
         pragma Loop_Invariant (Offset = Buffer'First + I);
         pragma Loop_Invariant (for all J in 1 .. I =>
           Wrapped.Nonce (J) = Buffer (Buffer'First + J - 1));
      end loop;

      pragma Assert (Offset = Buffer'First + 12);

      for I in Wrapped.Ciphertext'Range loop
         Wrapped.Ciphertext (I) := Buffer (Offset);
         Offset := Offset + 1;
         pragma Loop_Invariant (Offset = Buffer'First + 12 + I);
         pragma Loop_Invariant (for all J in 1 .. I =>
           Wrapped.Ciphertext (J) = Buffer (Buffer'First + 12 + J - 1));
      end loop;

      pragma Assert (Offset = Buffer'First + 44);

      for I in Wrapped.Tag'Range loop
         Wrapped.Tag (I) := Buffer (Offset);
         Offset := Offset + 1;
         pragma Loop_Invariant (Offset = Buffer'First + 44 + I);
         pragma Loop_Invariant (for all J in 1 .. I =>
           Wrapped.Tag (J) = Buffer (Buffer'First + 44 + J - 1));
      end loop;

      pragma Assert (Offset = Buffer'First + 60);

      Wrapped.Present := True;
      Success := True;

      --  MARMARAGAN: Final assertion verifies round-trip property
      pragma Assert (Is_Valid_Wrapped_Key (Wrapped));
   end Deserialize_Wrapped_Key_Pure;

   procedure Wipe_Wrapped_Key_Pure (Wrapped : in out Wrapped_Key) is
   begin
      Wrapped.Present := False;
      SparkPass.Crypto.Zeroize.Wipe (Wrapped.Nonce);
      SparkPass.Crypto.Zeroize.Wipe_Key (Wrapped.Ciphertext);
      SparkPass.Crypto.Zeroize.Wipe_Tag (Wrapped.Tag);

      --  MARMARAGAN: Assert statement verifies complete zeroization (100% success)
      pragma Assert (Is_Zeroed_Wrapped_Key (Wrapped));
   end Wipe_Wrapped_Key_Pure;

   procedure Wipe_Sealed_Share_Pure (Share : in out Sealed_Share) is
   begin
      SparkPass.Crypto.Shamir.Wipe_Share (Share.Share_Data);
      SparkPass.Crypto.Zeroize.Wipe (Share.Nonce);
      SparkPass.Crypto.Zeroize.Wipe_Tag (Share.Tag);

      --  MARMARAGAN: Assert for verification (100% success pattern)
      pragma Assert ((for all I in Share.Share_Data'Range => Share.Share_Data (I) = 0));
      pragma Assert ((for all I in Share.Nonce'Range => Share.Nonce (I) = 0));
      pragma Assert ((for all I in Share.Tag'Range => Share.Tag (I) = 0));
   end Wipe_Sealed_Share_Pure;

end SparkPass.Crypto.Wrapping.Pure;
