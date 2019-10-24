{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE FlexibleContexts    #-}
{-# LANGUAGE LambdaCase          #-}
{-# LANGUAGE RecordWildCards     #-}
{-# LANGUAGE TupleSections       #-}
{-# LANGUAGE TypeApplications    #-}
{-# LANGUAGE TypeOperators       #-}

module Parser.Base
  ( readDatabase
  , pprotect
  ) where

import           Control.Lens              (over, set, view, _1, _2)
import           Control.Monad.Reader      (ReaderT, ask, asks, filterM, lift,
                                            local, runReaderT, (>=>))
import           Data.ByteString           (ByteString, empty)
import           Data.ByteString.Char8     (unpack)
import           Data.Either               (fromRight)
import           Data.Functor              (($>), (<&>))

import           Config
import           Control.Monad             (liftM)
import           Crypto                    (applySalsa20, decryptPayload,
                                            genMasterKey, initSalsa20)
import           Crypto.Cipher.Salsa       as Salsa

import           Control.Monad.Reader      (runReaderT)
import           Data.Function             ((&))
import           Data.List                 (find, uncons)
import           Data.Maybe                (fromMaybe)
import           GHC.IO.Unsafe             (unsafePerformIO)
import           Parser.Binary             (parseConfig, parsePayload)

import           Data.ByteString.Lazy      (fromStrict)

import           Text.XML.HXT.Core         (SLA, XmlTree, accessState,
                                            changeAttrValue, changeState,
                                            getAttrValue, getChildren, getText,
                                            hasName, isA, isText, mkText,
                                            processAttrl, processChildren,
                                            processTopDown, runLA, runSLA, when,
                                            xreadDoc, (>>>))

import           Control.Applicative       ((<**>))
import           Data.Tree.NTree.TypeDefs  (NTree (NTree))
import           Text.XML.HXT.DOM.ShowXml  (xshow)
import           Text.XML.HXT.DOM.TypeDefs (XNode (..))
import qualified Text.XML.HXT.DOM.XmlNode  as XN (getText)

import qualified Data.ByteString.Base64    as Base64 (decode)
import qualified Data.ByteString.Char8     as CH (pack, unpack)

type ParserT = ReaderT KDBConfig (Either String)

type XMLParserT = ReaderT XmlTree (Either String)

readDatabase :: ByteString -> [ByteString] -> Either String Database
readDatabase bs creds = getConfig bs creds >>= runReaderT (decrypt >>= flip local parseXML . set payload)

getConfig :: ByteString -> [ByteString] -> Either String KDBConfig
getConfig bs creds = parseConfig bs <&> set credentials creds

decrypt :: ParserT ByteString
decrypt = do
  config <- ask
  rawData <- decryptPayload
  let x = parsePayload config rawData
  case x of
    Left e  -> lift $ Left e
    Right s -> return s

pprotect :: SLA (String, Salsa.State) XmlTree XmlTree
pprotect = processTopDown $ unprotec `when` (getAttrValue "Protected" >>> isA (== "True"))
  where
    unprotec =
      processChildren $
      changeState (\(_, salsa) b -> applySalsa20 salsa (fromMaybe "" (XN.getText b))) >>>
      accessState (\(p, _) _ -> p) >>>
      mkText >>> processAttrl (changeAttrValue (const "False") `when` hasName "Protected")

parseXML :: ParserT Database
parseXML = do
  config <- ask
  xmlBytes <- asks $ view payload
  salsaKey <- asks $ view (header . protectedStreamKey)
  let doc =
        runSLA
          (xreadDoc >>> pprotect >>> getChildren >>> hasName "Root" >>> getChildren >>> hasName "Group")
          ("", initSalsa20 salsaKey)
          (unpack xmlBytes)
  let rootGroup = head $ snd doc
  let groups = runReaderT getGroup rootGroup
  case groups of
    Left e  -> lift $ Left e
    Right g -> return $ Database config g

nvlHead =
  \case
    [] -> return ""
    w:_ -> return w

tag :: String -> XMLParserT String
tag t = do
  x <- ask
  case runLA (getChildren >>> hasName t) x of
    [] -> lift $ Left $ "no value for tag " ++ t ++ " found \ncontext: " ++ xshow [x]
    t:_ -> nvlHead $ runLA (getChildren >>> isText >>> getText) t

tags :: String -> XMLParserT [XmlTree]
tags t = asks (runLA (getChildren >>> hasName t))

withChild f e = local (const e) f

getGroup :: XMLParserT DBGroup
getGroup = do
  gUuid <- tag "UUID"
  name <- tag "Name"
  entries <- tags "Entry" >>= mapM (withChild getEntry)
  subgroups <- tags "Group" >>= mapM (withChild getGroup)
  return $ DBGroup {..}

getEntry :: XMLParserT DBEntry
getEntry = do
  eUuid <- tag "UUID"
  strs <- tags "String"
  let get key = filterM (withChild $ tag "Key" <**> return (== key)) strs >>= mapM (withChild $ tag "Value") >>= nvlHead
  username <- get "UserName"
  password <- get "Password" <&> (CH.pack >>> Base64.decode >>> fromRight empty >>> CH.unpack)
  title <- get "Title"
  notes <- get "Notes"
  url <- get "URL"
  return DBEntry {..}
