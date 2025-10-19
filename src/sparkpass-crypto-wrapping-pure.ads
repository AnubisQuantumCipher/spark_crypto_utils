pragma SPARK_Mode (On);
with SparkPass.Types; use SparkPass.Types;

--  SPARK-verified pure operations for Wrapping module
--  This child package contains serialization/deserialization logic
--  that does not depend on FFI, allowing full SPARK verification.
--
--  MARMARAGAN STRATEGY: Separate pure logic from FFI to maximize proof success
private package SparkPass.Crypto.Wrapping.Pure is

   --  Ghost predicates are already in parent spec with inline for proof

   --  SPARK-verified serialization (pure data transformation)
   --  MARMARAGAN: Relaxed_Initialization allows piecewise initialization proof
   procedure Serialize_Wrapped_Key_Pure
     (Wrapped : in     Wrapped_Key;
      Buffer  : out    Wrapped_Key_Array;
      Success : out    Boolean)
   with
     Global => null,
     Relaxed_Initialization => Buffer,
     Pre    => Wrapped.Present and then
               Buffer'Length = Wrapped_Key_Size,
     Post   => (if Success then
                 (Buffer'Initialized and then
                  Buffer'Length = 60 and then
                  (for all I in 1 .. 12 =>
                    Buffer (Buffer'First + I - 1) = Wrapped.Nonce (I)) and then
                  (for all I in 1 .. 32 =>
                    Buffer (Buffer'First + 12 + I - 1) = Wrapped.Ciphertext (I)) and then
                  (for all I in 1 .. 16 =>
                    Buffer (Buffer'First + 44 + I - 1) = Wrapped.Tag (I))));

   --  SPARK-verified deserialization (pure data transformation)
   --  MARMARAGAN: Relaxed_Initialization allows piecewise initialization proof
   procedure Deserialize_Wrapped_Key_Pure
     (Buffer  : in     Wrapped_Key_Array;
      Wrapped : out    Wrapped_Key;
      Success : out    Boolean)
   with
     Global => null,
     Relaxed_Initialization => Wrapped,
     Pre    => Buffer'Length = Wrapped_Key_Size,
     Post   => (if Success then
                 (Wrapped'Initialized and then
                  Wrapped.Present and then
                  Is_Valid_Wrapped_Key (Wrapped) and then
                  (for all I in 1 .. 12 =>
                    Wrapped.Nonce (I) = Buffer (Buffer'First + I - 1)) and then
                  (for all I in 1 .. 32 =>
                    Wrapped.Ciphertext (I) = Buffer (Buffer'First + 12 + I - 1)) and then
                  (for all I in 1 .. 16 =>
                    Wrapped.Tag (I) = Buffer (Buffer'First + 44 + I - 1))));

   --  SPARK-verified wipe (pure data transformation)
   procedure Wipe_Wrapped_Key_Pure (Wrapped : in out Wrapped_Key)
   with
     Global => null,
     Post   => Is_Zeroed_Wrapped_Key (Wrapped);

   --  SPARK-verified wipe for sealed share
   procedure Wipe_Sealed_Share_Pure (Share : in out Sealed_Share)
   with
     Global => null,
     Post   => (for all I in Share.Share_Data'Range => Share.Share_Data (I) = 0) and then
               (for all I in Share.Nonce'Range => Share.Nonce (I) = 0) and then
               (for all I in Share.Tag'Range => Share.Tag (I) = 0);

end SparkPass.Crypto.Wrapping.Pure;
