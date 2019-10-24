{-# LANGUAGE BangPatterns #-}

module Renderer
  ( writeDatabase
  ) where

import           Bytes                    (fileSignature, fileVersion,
                                           prettyPrint)
import           Config
import           Control.Applicative      (liftA2)
import           Control.Lens             (view)
import           Control.Monad.Reader     (ReaderT, ask, asks, lift, runReader,
                                           runReaderT, (>=>))
import           Data.ByteString.Builder  (Builder, byteString, lazyByteString,
                                           toLazyByteString, word16LE, word32LE,
                                           word64LE, word8)
import           Data.ByteString.Lazy     (ByteString, empty, fromStrict,
                                           length, pack, replicate, toStrict)
import           Data.Word                (Word16, Word32, Word8)
import           Prelude                  hiding (length, replicate)

import qualified Crypto.Hash.SHA256       as SHA256 (hash)

import           Crypto                   (compress, decompress, encryptPayload,
                                           initSalsa20)
import           GHC.IO.Unsafe            (unsafePerformIO)
import           Parser.Base              (pprotect)
import           Text.XML.HXT.Core        (ArrowXml, XmlTree, hasName,
                                           indentDoc, mkelem, root, runLA,
                                           runSLA, runX, sattr, selem, txt,
                                           (>>>))
import           Text.XML.HXT.DOM.ShowXml (xshow)

import qualified Data.ByteString.Base64   as Base64 (encode)
import qualified Data.ByteString.Char8    as CH (pack, unpack)
import           Data.String              (fromString)

type DBRenderer = ReaderT Database (Either String) Builder

writeDatabase :: Database -> Either String ByteString
writeDatabase = runReaderT $ toLazyByteString <$> writeHeader

writeHeader :: DBRenderer
writeHeader = foldr1 (liftA2 mappend) [writeVersion, writeEntries, writePayload]

writeVersion :: DBRenderer
writeVersion = return $ mconcat $ map byteString [fileSignature, fileVersion] ++ [word16LE 1, word16LE 3]

writeEntries :: DBRenderer
writeEntries = do
  header <- asks $ _header . config
  let getLazy f = fromStrict $ view f header
  return $
    writeEntry 2 (getLazy cipherId) <>
    writeEntryB 3 4 (word32LE . fromIntegral . fromEnum $ view compressionFlags header) <>
    writeEntry 4 (getLazy masterSeed) <>
    writeEntry 5 (getLazy transformSeed) <>
    writeEntryB 6 8 (word64LE $ view transformRounds header) <>
    writeEntry 7 (getLazy encryptionIV) <>
    writeEntry 8 (getLazy protectedStreamKey) <>
    writeEntry 9 (getLazy streamStartBytes) <>
    writeEntryB 10 4 (word32LE . fromIntegral . fromEnum $ view innerRandomStreamId header) <>
    writeEntry 0 (pack [0x0D, 0x0A, 0x0D, 0x0A])

writeEntry :: Word8 -> ByteString -> Builder
writeEntry id bs = word8 id <> word16LE len <> lazyByteString bs
  where
    len = fromIntegral $ length bs

writeEntryB :: Word8 -> Word16 -> Builder -> Builder
writeEntryB id len b = word8 id <> word16LE len <> b

writePayload :: DBRenderer
writePayload = do
  db <- ask
  let cfg = config db
      xTree = head $ makeXML db
      salsaKey = view (header . protectedStreamKey) cfg
      streamStart = view (header . streamStartBytes) cfg
      xml = snd $ runSLA pprotect ("", initSalsa20 salsaKey) xTree
      compression = view (header . compressionFlags) cfg
      compF =
        if compression == GZip
          then compress
          else id
      bData = compF . fromString $ xshow xml
      payload =
        toStrict . toLazyByteString $
        byteString streamStart <> writeBlock 0 (fromStrict $ SHA256.hash bData) (fromStrict bData) <>
        writeBlock 1 (replicate 32 0x0) empty
  case runReaderT (encryptPayload payload) cfg of
    Right str -> return $ byteString str
    Left e    -> lift $ Left e

writeBlock :: Word32 -> ByteString -> ByteString -> Builder
writeBlock id hash cont =
  word32LE id <> lazyByteString hash <> word32LE (fromIntegral $ length cont) <> lazyByteString cont

makeXML :: Database -> [XmlTree]
makeXML db = runLA (genRoot db >>> indentDoc) ()

genRoot :: ArrowXml a => Database -> a () XmlTree
genRoot (Database _ rootGroup) = selem "KeePassFile" [selem "Root" [genGroup rootGroup]]

genGroup :: ArrowXml a => DBGroup -> a () XmlTree
genGroup (DBGroup uuid name entries subgroups) =
  selem "Group" $ [selem "UUID" [txt uuid], selem "Name" [txt name]] ++ map genEntry entries ++ map genGroup subgroups

genEntry :: ArrowXml a => DBEntry -> a () XmlTree
genEntry (DBEntry uuid username password title notes url) =
  selem
    "Entry"
    [ selem "UUID" [txt uuid]
    , str "UserName" username
    , selem
        "String"
        [ selem "Key" [txt "Password"]
        , mkelem "Value" [sattr "Protected" "True"] [txt $ (CH.pack >>> Base64.encode >>> CH.unpack) password]
        ]
    , str "Title" title
    , str "Notes" notes
    , str "URL" url
    ]
  where
    str key value = selem "String" [selem "Key" [txt key], selem "Value" [txt value]]
