module Main where

import           Control.Monad
import           Control.Monad.IO.Class
import           Core
import           Data.IORef

import Config
--import           Graphics.UI.Gtk        hiding (Action, backspace)

main :: IO ()
main = do
  putStrLn "Enter path to the .kdbx file and master password"
  filePath <- getLine
  pass <- getLine
  db <- loadDatabase filePath pass
  case db of
    Left e -> putStrLn e
    Right d -> do
          let es = entries $ rootGroup d
          print es
--  st <- newIORef (Value "" Nothing)
--  void initGUI
--  window <- windowNew
--  loadDatabase "Database.kdbx"
--  window `on` deleteEvent $ do
--    liftIO mainQuit
--    return False
--  widgetShowAll window
--  mainGUI
