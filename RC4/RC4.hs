-------------------------------------------------------------
--
-- Author: Joao H de A Franco (jhafranco@gmail.com)
--
-- Description: RC4 implementation in Haskell
--
-- Date: 2013-02-22
--
-- License: Attribution-NonCommercial-ShareAlike 3.0 Unported
--          (CC BY-NC-SA 3.0)
--
-------------------------------------------------------------
module Crypto.RC4 (encrypt) where
import Data.Array (Array, array, (//), (!))
import Data.Char (chr, ord)
import Data.Bits (xor)

type ArrayRC4 = Array Int Int
type Index = Int
type Key = String
type Stream = String

-- Encrypt (or decrypt) using RC4 keystream
encrypt :: Key -> String -> String
encrypt k c = map chr $ zipWith xor (map ord (stream k)) (map ord c)
              where stream = prga . ksa

-- Pseudo-random generation algorithm (PRGA)                             
prga :: ArrayRC4 -> Stream
prga = prga' 0 0
  where prga' i j s = let i' = succ i `mod` 256
                          j' = (s ! i' + j) `mod` 256
                          s' = swap i' j' s
                          t = s' ! ((s ! i' + s ! j') `mod` 256)
                       in chr t : prga' i' j' s'

-- Key Scheduling Algorithm (KSA)
ksa :: Key -> ArrayRC4
ksa k = ksa' 0 0 $ array (0,255) [(i,i) | <- [0..255]]
  where ksa' 256 _ s = s
        ksa' i j s = let i' = i `mod` length k
                         j' = (j + s ! i + ord (k !! i')) `mod` 256
                     in ksa' (succ i) j' (swap j' i s)

-- Swap the values of S[i] and S[j]
swap :: Index -> Index -> ArrayRC4 -> ArrayRC4
swap i j s = if i /= j then s // [(i, s ! j), (j, s ! i)] else s