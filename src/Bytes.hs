module Bytes
  ( prettyPrint
  , fromBytesLE
  , fileSignature
  , fileVersion
  , fixedIV
  ) where

import           Data.Bits       (shiftL, (.|.))
import           Data.ByteString (ByteString, foldr, pack, unpack)
import           Data.Word       (Word64, Word8)
import           Numeric         (showHex)
import           Prelude         hiding (foldr)

prettyPrint :: ByteString -> String
prettyPrint = concatMap (`showHex` "\\") . unpack

fromBytesLE :: (Integral n) => ByteString -> n
fromBytesLE = fromIntegral . foldr op 0
  where
    op :: Word8 -> Word64 -> Word64
    op val acc = (acc `shiftL` 8) .|. fromIntegral val

fileSignature :: ByteString
fileSignature = pack [0x03, 0xd9, 0xa2, 0x9a]

fileVersion :: ByteString
fileVersion = pack [0x67, 0xfb, 0x4b, 0xb5]

fixedIV :: ByteString
fixedIV = pack [0xe8, 0x30, 0x09, 0x4b, 0x97, 0x20, 0x5d, 0x2a]
