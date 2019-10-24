{-# LANGUAGE BlockArguments   #-}
{-# LANGUAGE TypeApplications #-}

module Crypto
  ( genMasterKey
  , encryptPayload
  , decryptPayload
  , initSalsa20
  , applySalsa20
  , compress
  , decompress
  ) where

import           Control.Lens           (over, view, _1)
import           Control.Monad.Reader   (ReaderT, ask, asks, lift, runReaderT,
                                         (>=>))
import           Data.ByteString        (ByteString, concat, empty, pack)
import qualified Data.ByteString.Char8  as CH (pack, unpack)
import           Data.ByteString.Lazy   (fromStrict, toStrict)

import           Prelude                hiding (concat)

import           Control.Arrow          ((>>>))
import           Data.Functor           ((<&>))

import qualified Crypto.Cipher.AES128   as AES128
import           Crypto.Cipher.Salsa    as Salsa
import qualified Crypto.Hash.SHA256     as SHA256
import           Crypto.Types
import qualified Data.ByteString.Base64 as Base64 (decode, encode)

import           Bytes                  (fixedIV)
import qualified Codec.Compression.GZip as GZip (compress, decompress)
import           Data.Either            (fromRight)
import           Data.Function          ((&))
import           GHC.IO.Unsafe          (unsafePerformIO)

import           Config

type CryptoT = ReaderT KDBConfig (Either String)

decryptPayload :: CryptoT ByteString
decryptPayload = do
  mKey <- genMasterKey
  iv <- asks . view $ header . encryptionIV
  payload <- asks $ view payload
  key <- genAESKey mKey
  return $ fst $ AES128.unCbc key (IV iv) payload

encryptPayload :: ByteString -> CryptoT ByteString
encryptPayload payload = do
  mKey <- genMasterKey
  iv <- asks . view $ header . encryptionIV
  key <- genAESKey mKey
  return $ fst $ AES128.cbc key (IV iv) payload

initSalsa20 :: ByteString -> Salsa.State
initSalsa20 key = Salsa.initialize 20 (SHA256.hash key) fixedIV

applySalsa20 :: Salsa.State -> String -> (String, Salsa.State)
applySalsa20 sa =
  CH.pack >>> Base64.decode >>> fromRight empty >>> Salsa.combine sa >>> over _1 (CH.unpack . Base64.encode)

genCompKey :: CryptoT ByteString
genCompKey = asks view credentials <&> (map SHA256.hash >>> concat >>> SHA256.hash)

genMasterKey :: CryptoT ByteString
genMasterKey = do
  compKey <- genCompKey
  rounds <- (asks . view $ header . transformRounds) <&> fromIntegral
  seed <- ask . view $ header . transformSeed
  transSeed <- genAESKey seed
  let transform = foldr (>=>) return $ replicate rounds $ genTransformKey transSeed
  transformedKey <- transform compKey <&> SHA256.hash
  masterSeed <- ask . view $ header . masterSeed
  return $ SHA256.hash $ concat [masterSeed, transformedKey]

genTransformKey :: AES128.AESKey256 -> ByteString -> CryptoT ByteString
genTransformKey seed key = return $ AES128.ecb seed key

genAESKey :: ByteString -> CryptoT AES128.AESKey256
genAESKey seed = do
  let key = AES128.buildKey @AES128.AESKey256 seed
  case key of
    Nothing  -> lift $ Left "couldn't initialize AES128 context"
    Just key -> return key

compress :: ByteString -> ByteString
compress = fromStrict >>> GZip.compress >>> toStrict

decompress :: ByteString -> ByteString
decompress = fromStrict >>> GZip.decompress >>> toStrict
