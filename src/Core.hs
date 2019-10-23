{-# LANGUAGE BangPatterns #-}

module Core
  ( loadDatabase
  ) where

import           Data.ByteString      (readFile)
import           Data.ByteString.Lazy (writeFile)
import           Prelude              hiding (readFile, writeFile)
import qualified System.IO            as IO (IOMode (ReadMode), withFile)

import           Bytes                (prettyPrint)
import           Config
import           Data.Functor         ((<&>))
import           Data.String          (fromString)
import           Parser.Base          (readDatabase)
import           Renderer             (writeDatabase)

loadDatabase :: String -> String -> IO (Either String Database)
loadDatabase filePath password = do
  contents <- readFile filePath
  return $ readDatabase contents [fromString password]
--  case db of
--    Right d -> do
--      print $ show (rootGroup d)
--      let bs = writeDatabase d
--      writeFile "out.kdbx" bs
--      return ()
--    Left e -> print e
--  return ()
