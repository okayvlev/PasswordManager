
import           Config
import           Control.Exception (evaluate)
import           Core
import           Test.Hspec
import           Test.QuickCheck

main :: IO ()
main =
  hspec $
  describe "Functional test" $
  it "test consistency" $ do
    Right db <- loadDatabase "test/res/Test.kdbx" "abacaba"
    saveDatabase "test/res/out.kdbx" db
    Right db2 <- loadDatabase "test/res/out.kdbx" "abacaba"
    show (rootGroup db) `shouldBe` show (rootGroup db2)
