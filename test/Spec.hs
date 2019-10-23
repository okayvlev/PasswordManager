import           Control.Exception (evaluate)
import           Core
import           Test.Hspec
import           Test.QuickCheck

main :: IO ()
main =
  hspec $
  describe "Functional test" $ do it "load database" $ let x = loadDatabase "test/res/Test.kdbx" "abacaba" in print ""
