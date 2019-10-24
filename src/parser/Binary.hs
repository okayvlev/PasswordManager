{-# LANGUAGE LambdaCase       #-}
{-# LANGUAGE RecordWildCards  #-}
{-# LANGUAGE TypeApplications #-}

module Parser.Binary
  ( parseConfig
  , parsePayload
  ) where

import           Control.Monad.State  (StateT, get, lift, put, runStateT,
                                       unless, when)
import           Data.ByteString      (ByteString, concat, length, pack,
                                       replicate, splitAt)
import           Data.Function        ((&))
import           Data.List            (find)
import           Data.Sort            (sortOn)
import           Data.Word            (Word32)
import           Prelude              hiding (concat, length, replicate,
                                       splitAt)

import qualified Crypto.Hash.SHA256   as SHA256 (hash)

import           Bytes
import           Config
import           Control.Arrow        ((>>>))
import           Control.Lens         (over, view)
import           Crypto               (decompress)
import           Data.ByteString.Lazy (fromStrict, toStrict)
import           GHC.IO.Unsafe        (unsafePerformIO)

type BinParserT = StateT ByteString (Either String)

data Block =
  Block
    { dwBlockId :: Word32
    , sHash     :: ByteString
    , pbData    :: ByteString
    }
  deriving (Show)

processBytes :: Int -> BinParserT ByteString
processBytes n = do
  bs <- get
  let (x, xs) = splitAt n bs
  when (length x < n) $ lift $ Left "unexpected end of file"
  put xs
  return x

parseConfig :: ByteString -> Either String KDBConfig
parseConfig =
  (\case
     Left e -> Left e
     Right (c, _) -> Right c) .
  parseConfig'

parseConfig' :: ByteString -> Either String (KDBConfig, ByteString)
parseConfig' =
  runStateT $ do
    validateSignature
    validateVersion
    v <- getVersion
    h <- getHeader
    p <- get
    return $ KDBConfig v h p []

parsePayload :: KDBConfig -> ByteString -> Either String ByteString
parsePayload config =
  (\case
     Left e -> Left e
     Right (c, _) -> Right c) .
  parsePayload' config

parsePayload' :: KDBConfig -> ByteString -> Either String (ByteString, ByteString)
parsePayload' config =
  runStateT $ do
    let expectedStart = view (header . streamStartBytes) config
    streamStart <- processBytes 32
    when (streamStart /= expectedStart) $ lift $ Left "incorrect password"
    bs <- sortOn dwBlockId <$> getPayload
    let contents = concat $ map pbData bs
    let decode =
          if view (header . compressionFlags) config == GZip
            then decompress
            else id
    return $ decode contents

getPayload :: BinParserT [Block]
getPayload = do
  block@(Block sid sHash pbData) <- getBlock
  if length pbData == 0 && sHash == replicate 32 0x0
    then return [block]
    else do
      unless (sHash == SHA256.hash pbData) $ lift $ Left "file is corrupted (data hashes mismatch)"
      other <- getPayload
      return $ block : other

getBlock :: BinParserT Block
getBlock = do
  dwBlockId <- fromBytesLE <$> processBytes 4
  sHash <- processBytes 32
  dwBlockSize <- fromBytesLE <$> processBytes 4
  pbData <- processBytes dwBlockSize
  return $ Block dwBlockId sHash pbData

validateSignature :: BinParserT ()
validateSignature = do
  x <- processBytes 4
  unless (x == fileSignature) $ lift $ Left "invalid signature"

validateVersion :: BinParserT ()
validateVersion = do
  x <- processBytes 4
  unless (x == fileVersion) $ lift $ Left "unsupported file version"

getVersion :: BinParserT Version
getVersion = do
  minor <- fromBytesLE <$> processBytes 2
  major <- fromBytesLE <$> processBytes 2
  return $ Version major minor

getHeader :: BinParserT Header
getHeader = do
  hs <- getHeaders
  let match' id = find (\h -> bId h == id) hs
      match id =
        case match' id of
          Nothing -> lift $ Left $ "header with bId " ++ show id ++ " not found"
          Just x -> return x
      getData id = bData <$> match id
  _cipherId <- getData CIPHERID
  _compressionFlags <- toEnum . fromBytesLE <$> getData COMPRESSIONFLAGS
  _masterSeed <- getData MASTERSEED
  _transformSeed <- getData TRANSFORMSEED
  _transformRounds <- fromBytesLE <$> getData TRANSFORMROUNDS
  _encryptionIV <- getData ENCRYPTIONIV
  _protectedStreamKey <- getData PROTECTEDSTREAMKEY
  _streamStartBytes <- getData STREAMSTARTBYTES
  _innerRandomStreamId <- toEnum . fromBytesLE <$> getData INNERRANDOMSTREAMID
  return $ Header {..}

getHeaders :: BinParserT [HeaderEntry]
getHeaders = do
  entry <- getHeaderEntryRaw
  if bId entry /= END
    then do
      other <- getHeaders
      return $ entry : other
    else return [entry]

getHeaderEntryRaw :: BinParserT HeaderEntry
getHeaderEntryRaw = do
  bId <- toEnum . fromBytesLE <$> processBytes 1
  bLen <- fromBytesLE <$> processBytes 2
  bData <- processBytes bLen
  return $ HeaderEntry bId bLen bData
