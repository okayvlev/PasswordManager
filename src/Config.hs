{-# LANGUAGE TemplateHaskell #-}

module Config where

import           Bytes           (prettyPrint)
import           Control.Lens    (makeLenses)
import           Data.ByteString (ByteString)
import           Data.Word       (Word32, Word64)

data KDBConfig =
  KDBConfig
    { _version     :: Version
    , _header      :: Header
    , _payload     :: ByteString
    , _credentials :: [ByteString]
    }
  deriving (Show)

data Database =
  Database
    { config    :: KDBConfig
    , rootGroup :: DBGroup
    }
  deriving (Show)

data DBGroup =
  DBGroup
    { gUuid     :: String
    , name      :: String
    , entries   :: [DBEntry]
    , subgroups :: [DBGroup]
    }
  deriving (Show)

data DBEntry =
  DBEntry
    { eUuid    :: String
    , username :: String
    , password :: String
    , title    :: String
    , notes    :: String
    , url      :: String
    }
  deriving (Show)

data Version =
  Version
    { major :: Word32
    , minor :: Word32
    }
  deriving (Show)

data Header =
  Header
    { _cipherId            :: ByteString
    , _compressionFlags    :: PayloadType
    , _masterSeed          :: ByteString
    , _transformSeed       :: ByteString
    , _transformRounds     :: Word64
    , _encryptionIV        :: ByteString
    , _protectedStreamKey  :: ByteString
    , _streamStartBytes    :: ByteString
    , _innerRandomStreamId :: EncryptionType
    }
  deriving (Show)

data HeaderEntry =
  HeaderEntry
    { bId   :: HeaderEntryId
    , bSize :: Int
    , bData :: ByteString
    }

instance Show HeaderEntry where
  show (HeaderEntry bId bSize bData) = "{" ++ show bId ++ "[" ++ show bSize ++ "]: " ++ show (prettyPrint bData) ++ "}"

data HeaderEntryId
  = END
  | COMMENT
  | CIPHERID
  | COMPRESSIONFLAGS
  | MASTERSEED
  | TRANSFORMSEED
  | TRANSFORMROUNDS
  | ENCRYPTIONIV
  | PROTECTEDSTREAMKEY
  | STREAMSTARTBYTES
  | INNERRANDOMSTREAMID
  deriving (Enum, Show, Eq)

data PayloadType
  = NotCompressed
  | GZip
  deriving (Enum, Show, Eq)

data EncryptionType
  = None
  | Arc4Variant
  | Salsa20
  deriving (Enum, Show, Eq)

makeLenses ''KDBConfig

makeLenses ''Header
