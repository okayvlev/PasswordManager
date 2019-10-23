{-# LANGUAGE BangPatterns #-}

module Renderer
  ( writeDatabase
  ) where

import           Bytes                    (fileSignature, fileVersion)
import           Config
import           Control.Applicative      (liftA2, liftA3)
import           Control.Lens             (view)
import           Control.Monad.Reader     (Reader, ask, asks, lift, runReader,
                                           (>=>))
import           Data.ByteString.Builder  (Builder, byteString, lazyByteString,
                                           toLazyByteString, word16LE, word32LE,
                                           word64LE, word8)
import           Data.ByteString.Lazy     (ByteString, empty, fromStrict,
                                           length, pack)
import           Data.Word                (Word16, Word8)
import           Prelude                  hiding (length)

import           Crypto                   (initSalsa20)
import           GHC.IO.Unsafe            (unsafePerformIO)
import           Parser.Base              (pprotect)
import           Text.XML.HXT.Core        (ArrowXml, XmlTree, hasName,
                                           indentDoc, mkelem, root, runLA,
                                           runSLA, runX, sattr, selem, txt,
                                           (>>>))
import           Text.XML.HXT.DOM.ShowXml (xshow)

import qualified Data.ByteString.Base64   as Base64 (encode)
import qualified Data.ByteString.Char8    as CH (pack, unpack)

type DBRenderer = Reader Database Builder

writeDatabase :: Database -> ByteString
writeDatabase = runReader $ toLazyByteString <$> writeHeader

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
    writeEntryB 10 4 (word32LE . fromIntegral . fromEnum $ view innerRandomStreamId header)

writeEntry :: Word8 -> ByteString -> Builder
writeEntry id bs = word8 id <> word16LE len <> lazyByteString bs
  where
    len = fromIntegral $ length bs

writeEntryB :: Word8 -> Word16 -> Builder -> Builder
writeEntryB id len b = word8 id <> word16LE len <> b

writePayload :: DBRenderer
writePayload = do
  db <- ask
  let x = head $ makeXML db
  let salsaKey = view (header . protectedStreamKey) (config db)
  let xxx = snd $ runSLA pprotect ("", initSalsa20 salsaKey) x
  return $ word16LE 1
--  let !xx = unsafePerformIO $ putStrLn $ xshow xxx

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
        [mkelem "Password" [sattr "Protected" "True"] [txt $ (CH.pack >>> Base64.encode >>> CH.unpack) password]]
    , str "Title" title
    , str "Notes" notes
    , str "URL" url
    ]
  where
    str key value = selem "String" [selem "Key" [txt key], selem "Value" [txt value]]
