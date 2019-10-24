module Core
  ( loadDatabase
  , saveDatabase
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
  let db = readDatabase contents [fromString password]
  return db

saveDatabase :: String -> Database -> IO (Either String ())
saveDatabase filePath db = do
  let contents = writeDatabase db
  case contents of
    Left e -> return $ Left e
    Right c -> do
      writeFile filePath c
      return $ Right ()
