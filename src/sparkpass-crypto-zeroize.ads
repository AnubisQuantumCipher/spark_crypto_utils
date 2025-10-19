pragma SPARK_Mode (On);
with Interfaces;
with SparkPass.Types; use SparkPass.Types;

package SparkPass.Crypto.Zeroize is
   pragma Preelaborate;
   use type Interfaces.Unsigned_8;

   --  Ghost predicate for verification (used in contracts)
   function Is_Zeroed_Ghost (Buffer : Byte_Array) return Boolean is
     (for all I in Buffer'Range => Buffer (I) = 0)
   with
     Ghost,
     Global  => null,
     Depends => (Is_Zeroed_Ghost'Result => Buffer);

   --  Runtime check version (executable, for testing)
   function Is_Zeroed (Buffer : Byte_Array) return Boolean
   with
     Global  => null,
     Depends => (Is_Zeroed'Result => Buffer),
     Post    => Is_Zeroed'Result = Is_Zeroed_Ghost (Buffer);

   procedure Wipe (Buffer : in out Byte_Array)
     with
       Global  => null,
       Depends => (Buffer => Buffer),
       Post    => Is_Zeroed_Ghost (Buffer);

   procedure Wipe_Key (Buffer : in out Key_Array)
     with
       Global  => null,
       Depends => (Buffer => Buffer),
       Post    => Is_Zeroed_Ghost (Byte_Array (Buffer));

   procedure Wipe_Tag (Buffer : in out Tag_Array)
     with
       Global  => null,
       Depends => (Buffer => Buffer),
       Post    => Is_Zeroed_Ghost (Byte_Array (Buffer));

   procedure Wipe_Chain (Buffer : in out Chain_Key_Array)
     with
       Global  => null,
       Depends => (Buffer => Buffer),
       Post    => Is_Zeroed_Ghost (Byte_Array (Buffer));

   --  Constant-time comparison of byte arrays
   --  Returns True if arrays are equal, False otherwise
   --  Implementation uses pure SPARK XOR accumulation for provability
   function Equal (Left : Byte_Array; Right : Byte_Array) return Boolean
     with
       Global  => null,
       Depends => (Equal'Result => (Left, Right)),
       Pre     => Left'Length = Right'Length and then
                  Left'Length > 0 and then
                  Left'Length <= 65536,
       Post    => Equal'Result = (for all I in Left'Range =>
                    Left (I) = Right (I - Left'First + Right'First));
end SparkPass.Crypto.Zeroize;
