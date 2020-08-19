{-# LANGUAGE ForeignFunctionInterface, EmptyDataDecls #-}

module Codec.Encryption.DH (
    -- * Diffie-Hellman key exchange
    DHParams(..)
  , DHParamError(..)
  , Modulus
  , Generator
  , newDHParams
  , checkDHParams
  , generateKey
  , computeKey
  ) where

import Data.Bits (shiftL,shiftR,(.|.),testBit)
import Data.List
import Data.Word (Word8)
import Foreign.C (CInt(..),CUChar(..))
import Foreign.Marshal.Alloc (alloca)
import Foreign.Marshal.Array
    (peekArray,allocaArray,withArrayLen,mallocArray)
import Foreign.Ptr (Ptr,nullPtr)
import Foreign.Storable (Storable(..))
import System.IO.Unsafe (unsafePerformIO)

#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/engine.h>

-- Types -----------------------------------------------------------------------

type Generator = Int
type Modulus   = Integer

data DHParams = DHParams
  { dhPrivateKey :: [Word8]
  , dhPublicKey  :: [Word8]
  , dhGenerator  :: Generator
  , dhModulus    :: Modulus
  } deriving Show

data DHParamError
  = PNotPrime
  | PNotSafePrime
  | UnableToCheckGenerator
  | NotSuitableGenerator
  deriving Show


-- Utilities -------------------------------------------------------------------

roll :: [Word8] -> Integer
roll  = foldr step 0 . reverse
  where step n acc = acc `shiftL` 8 .|. fromIntegral n

unroll :: Integer -> [Word8]
unroll  = reverse . unfoldr step
  where
    step 0 = Nothing
    step n = Just (fromIntegral n, n `shiftR` 8)


withDH :: DHParams -> a -> (Ptr DHParams -> IO a) -> IO a
withDH ps a f = c_DH_new >>= \ptr -> if ptr == nullPtr
  then return a
  else do bin2bn (dhPrivateKey ps)       >>= c_DH_set_priv ptr
          bin2bn (dhPublicKey  ps)       >>= c_DH_set_pub  ptr
          bin2bn (unroll $ dhModulus ps) >>= c_DH_set_p  ptr
          bin2bn (unroll $ toInteger $ dhGenerator ps) >>= c_DH_set_g ptr
          res <- f ptr
          c_DH_free ptr
          return res


dhToDHParams :: Ptr DHParams -> IO DHParams
dhToDHParams ptr = do
  privKey <- bn2bin =<< c_DH_get0_privkey ptr
  pubKey  <- bn2bin =<< c_DH_get0_pubkey  ptr
  p       <- bn2bin =<< c_DH_get0_p       ptr
  g       <- bn2bin =<< c_DH_get0_g       ptr
  return $ DHParams { dhPrivateKey = privKey
                    , dhPublicKey  = pubKey
                    , dhGenerator  = fromInteger $ roll g
                    , dhModulus    = roll p
                    }

-- Diffie-Hellman --------------------------------------------------------------

newDHParams :: Int -> Generator -> IO (Maybe DHParams)
newDHParams len gen = do
  ptr <- c_DH_generate_parameters (toEnum len) (toEnum gen) nullPtr nullPtr
  if ptr == nullPtr
    then return Nothing
    else c_DH_generate_key ptr >>= \res -> case res of
      1 -> do ps <- dhToDHParams ptr
              c_DH_free ptr
              return (Just ps)
      _ -> return Nothing


generateKey :: Modulus -> Generator -> IO (Maybe DHParams)
generateKey p g = c_DH_new >>= \ptr -> if ptr == nullPtr
  then return Nothing
  else do bin2bn (unroll p)             >>= c_DH_set_p ptr
          bin2bn (unroll (toInteger g)) >>= c_DH_set_g ptr
          res <- c_DH_generate_key ptr
          case res of
            1 -> do ps <- dhToDHParams ptr
                    c_DH_free ptr
                    return (Just ps)
            _ -> return Nothing


codesToErrors :: Int -> [DHParamError]
codesToErrors n = foldl f [] flags
  where
    f fs (b,e) | testBit n b = e : fs
               | otherwise   = fs
    flags = [ (0, PNotPrime)
            , (1, PNotSafePrime)
            , (2, UnableToCheckGenerator)
            , (3, NotSuitableGenerator)
            ]


checkDHParams :: DHParams -> IO [DHParamError]
checkDHParams ps =
  withDH ps [] $ \dh    ->
  alloca       $ \codes ->
  do res <- c_DH_check dh codes
     case res of
       1 -> (codesToErrors . fromEnum) `fmap` peek codes
       _ -> return []


{-# NOINLINE computeKey #-}
computeKey :: [Word8] -> DHParams -> [Word8]
computeKey pubKey ps = unsafePerformIO $
  withDH ps []                  $ \dh   ->
  c_DH_size dh                >>= \size ->
  allocaArray (fromEnum size)   $ \key  ->
  withBIGNUM pubKey             $ \pk   ->
  do res <- c_DH_compute_key key pk dh
     case res of
       (-1) -> return []
       _    -> map (toEnum . fromEnum) `fmap` peekArray (fromEnum size) key


foreign import ccall unsafe "openssl/dh.h DH_new"
  c_DH_new :: IO (Ptr DHParams)
foreign import ccall unsafe "openssl/dh.h DH_generate_parameters"
  c_DH_generate_parameters :: CInt -> CInt -> Ptr () -> Ptr ()
                           -> IO (Ptr DHParams)
foreign import ccall unsafe "openssl/dh.h DH_generate_key"
  c_DH_generate_key :: Ptr DHParams -> IO CInt
foreign import ccall unsafe "openssl/dh.h DH_compute_key"
  c_DH_compute_key :: Ptr CUChar -> Ptr BIGNUM -> Ptr DHParams -> IO CInt
foreign import ccall unsafe "openssl/dh.h DH_check"
  c_DH_check :: Ptr DHParams -> Ptr CInt -> IO CInt
foreign import ccall unsafe "openssl/dh.h DH_size"
  c_DH_size :: Ptr DHParams -> IO CInt
foreign import ccall "openssl/dh.h DH_free"
  c_DH_free :: Ptr DHParams -> IO ()


-- OpenSSL BIGNUM --------------------------------------------------------------

data BIGNUM


withBIGNUM :: [Word8] -> (Ptr BIGNUM -> IO a) -> IO a
withBIGNUM bs f = do
  bn  <- bin2bn bs
  res <- f bn
  c_BN_free bn
  return res


bin2bn :: [Word8] -> IO (Ptr BIGNUM)
bin2bn bs = withArrayLen (map (toEnum . fromEnum) bs) $ \len array ->
  c_BN_bin2bn array (toEnum $ fromEnum len) nullPtr


bn2bin :: Ptr BIGNUM -> IO [Word8]
bn2bin ptr = do
  len   <- numBytes ptr
  array <- mallocArray len
  size  <- c_BN_bn2bin ptr array
  list  <- peekArray len array
  return $ map (toEnum . fromEnum) $ take (fromEnum size) list


-- | Figure out how many bytes are used by a BIGNUM
numBytes :: Ptr BIGNUM -> IO Int
numBytes ptr = f `fmap` c_BN_num_bits ptr
  where f bits = (fromEnum bits + 7) `div` 8


foreign import ccall unsafe "openssl/bn.h BN_bin2bn"
  c_BN_bin2bn :: Ptr CUChar -> CInt -> Ptr BIGNUM -> IO (Ptr BIGNUM)
foreign import ccall unsafe "openssl/bn.h BN_bn2bin"
  c_BN_bn2bin :: Ptr BIGNUM -> Ptr CUChar -> IO CInt
foreign import ccall unsafe "openssl/bn.h BN_free"
  c_BN_free :: Ptr BIGNUM -> IO ()
foreign import ccall unsafe "openssl/bn.h BN_num_bits"
  c_BN_num_bits :: Ptr BIGNUM -> IO CInt
foreign import ccall unsafe "openssl/dh.h DH_get0_priv_key"
  c_DH_get0_privkey :: Ptr DHParams -> IO (Ptr BIGNUM)
foreign import ccall unsafe "openssl/dh.h DH_get0_pub_key"
  c_DH_get0_pubkey :: Ptr DHParams -> IO (Ptr BIGNUM)
foreign import ccall unsafe "openssl/dh.h DH_get0_p"
  c_DH_get0_p :: Ptr DHParams -> IO (Ptr BIGNUM)
foreign import ccall unsafe "openssl/dh.h DH_get0_g"
  c_DH_get0_g :: Ptr DHParams -> IO (Ptr BIGNUM)
foreign import ccall unsafe "openssl/dh.h DH_get0_q"
  c_DH_get0_q :: Ptr DHParams -> IO (Ptr BIGNUM)
foreign import ccall unsafe "openssl/dh.h DH_set0_pqg"
  c_DH_set_pqg :: Ptr DHParams -> Ptr BIGNUM -> Ptr BIGNUM -> Ptr BIGNUM -> IO Int
c_DH_set_p :: Ptr DHParams -> Ptr BIGNUM -> IO Int
c_DH_set_p d x = c_DH_set_pqg d x nullPtr nullPtr
c_DH_set_q :: Ptr DHParams -> Ptr BIGNUM -> IO Int
c_DH_set_q d x = c_DH_set_pqg d nullPtr x nullPtr
c_DH_set_g :: Ptr DHParams -> Ptr BIGNUM -> IO Int
c_DH_set_g d x = c_DH_set_pqg d nullPtr nullPtr x

foreign import ccall unsafe "openssl/dh.h DH_set0_key"
  c_DH_set_key :: Ptr DHParams -> Ptr BIGNUM -> Ptr BIGNUM -> IO ()

c_DH_set_pub :: Ptr DHParams -> Ptr BIGNUM -> IO ()
c_DH_set_pub d x = c_DH_set_key d x nullPtr

c_DH_set_priv :: Ptr DHParams -> Ptr BIGNUM -> IO ()
c_DH_set_priv d x = c_DH_set_key d nullPtr x
