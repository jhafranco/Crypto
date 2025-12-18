#!/usr/bin/env python3
#
# Author: Joao H de A Franco (jhafranco@gmail.com)
#
# Description: AES implementation in Python
#
# Date: 2013-06-02 (version 1.1)
#       2012-01-16 (version 1.0)
#
# License: Attribution-NonCommercial-ShareAlike 3.0 Unported
#          (CC BY-NC-SA 3.0)
#===========================================================
import sys
from itertools import repeat
from functools import reduce
from copy import copy

__all__ = ["setKey","encrypt","decrypt"]

def memoize(func):
    """Memoization function"""
    memo = {}
    def helper(x):
        if x not in memo:
            memo[x] = func(x)
        return memo[x]
    return helper

def mult(p1,p2):
    """Multiply two polynomials in GF(2^8)/x^8+x^4+x^3+x+1"""
    p = 0
    while p2:
        if p2&0x01:
            p ^= p1
        p1 <<= 1
        if p1&0x100:
            p1 ^= 0x1b
        p2 >>= 1
    return p&0xff

# Auxiliary one-parameter functions defined for memoization
# (to speed up multiplication in GF(2^8))

@memoize
def x2(y):
    """Multiplication by 2"""
    return mult(2,y)

@memoize
def x3(y):
    """Multiplication by 3"""
    return mult(3,y)

@memoize
def x9(y):
    """Multiplication by 9"""
    return mult(9,y)

@memoize
def x11(y):
    """Multiplication by 11"""
    return mult(11,y)

@memoize
def x13(y):
    """Multiplication by 13"""
    return mult(13,y)

@memoize
def x14(y):
    """Multiplication by 14"""
    return mult(14,y)

class AES:
    """Class definition for AES objects"""
    keySizeTable = {"SIZE_128":16,
                    "SIZE_192":24,
                    "SIZE_256":32}
    wordSizeTable = {"SIZE_128":44,
                     "SIZE_192":52,
                     "SIZE_256":60}
    numberOfRoundsTable = {"SIZE_128":10,
                           "SIZE_192":12,
                           "SIZE_256":14}
    cipherModeTable = {"MODE_ECB":1,
                       "MODE_CBC":2}
    paddingTable = {"NoPadding":0,
                    "PKCS5Padding":1}
    # S-Box
    sBox = (0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,
            0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
            0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,
            0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
            0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,
            0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
            0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,
            0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
            0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,
            0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
            0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,
            0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
            0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,
            0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
            0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,
            0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
            0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,
            0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
            0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,
            0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
            0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,
            0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
            0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,
            0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
            0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,
            0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
            0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,
            0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
            0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,
            0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
            0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,
            0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16)
    # Inverse S-Box
    invSBox = (0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,
               0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
               0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,
               0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
               0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,
               0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
               0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,
               0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
               0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,
               0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
               0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,
               0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
               0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,
               0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
               0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,
               0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
               0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,
               0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
               0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,
               0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
               0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,
               0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
               0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,
               0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
               0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,
               0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
               0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,
               0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
               0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,
               0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
               0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,
               0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d)

    # Instance variables
    wordSize = None
    w = [None]*60 # Round subkeys list
    keyDefined = None # Key definition flag
    numberOfRounds = None
    cipherMode = None
    padding = None # Padding scheme
    ivEncrypt = None # Initialization
    ivDecrypt = None #  vectors

    def __init__(self,mode,padding = "NoPadding"):
        """Create a new instance of an AES object"""
        try:
            assert mode in AES.cipherModeTable
        except AssertionError:
            print("Cipher mode not supported:",mode)
            sys.exit("ValueError")
        self.cipherMode = mode
        try:
            assert padding in AES.paddingTable
        except AssertionError:
            print("Padding scheme not supported:",padding)
            sys.exit(ValueError)
        self.padding = padding
        self.keyDefined = False

    def intToList(self,number):
        """Convert an 16-byte number into a 16-element list"""
        return [(number>>i)&0xff for i in reversed(range(0,128,8))]

    def intToList2(self,number):
        """Converts an integer into one (or more) 16-element list"""
        lst = []
        while number:
            lst.append(number&0xff)
            number >>= 8
        m = len(lst)%16
        if m == 0 and len(lst) != 0:
            return lst[::-1]
        else:
            return list(bytes(16-m)) + lst[::-1]

    def listToInt(self,lst):
        """Convert a list into a number"""
        return reduce(lambda x,y:(x<<8)+y,lst)

    def wordToState(self,wordList):
        """Convert list of 4 words into a 16-element state list"""
        return [(wordList[i]>>j)&0xff
                for j in reversed(range(0,32,8)) for i in range(4)]

    def listToState(self,list):
        """Convert a 16-element list into a 16-element state list"""
        return [list[i+j] for j in range(4) for i in range(0,16,4)]

    stateToList = listToState # this function is an involution

    def subBytes(self,state):
        """SubBytes transformation"""
        return [AES.sBox[e] for e in state]

    def invSubBytes(self,state):
        """Inverse SubBytes transformation"""
        return [AES.invSBox[e] for e in state]

    def shiftRows(self,s):
        """ShiftRows transformation"""
        return s[:4]+s[5:8]+s[4:5]+s[10:12]+s[8:10]+s[15:]+s[12:15]

    def invShiftRows(self,s):
        """Inverse ShiftRows transformation"""
        return s[:4]+s[7:8]+s[4:7]+s[10:12]+s[8:10]+s[13:]+s[12:13]

    def mixColumns(self,s):
        """MixColumns transformation"""
        return [x2(s[i])^x3(s[i+4])^   s[i+8] ^   s[i+12]  for i in range(4)]+ \
               [   s[i] ^x2(s[i+4])^x3(s[i+8])^   s[i+12]  for i in range(4)]+ \
               [   s[i] ^   s[i+4] ^x2(s[i+8])^x3(s[i+12]) for i in range(4)]+ \
               [x3(s[i])^   s[i+4] ^   s[i+8] ^x2(s[i+12]) for i in range(4)]

    def invMixColumns(self,s):
        """Inverse MixColumns transformation"""
        return [x14(s[i])^x11(s[i+4])^x13(s[i+8])^ x9(s[i+12]) for i in range(4)]+ \
               [ x9(s[i])^x14(s[i+4])^x11(s[i+8])^x13(s[i+12]) for i in range(4)]+ \
               [x13(s[i])^ x9(s[i+4])^x14(s[i+8])^x11(s[i+12]) for i in range(4)]+ \
               [x11(s[i])^x13(s[i+4])^ x9(s[i+8])^x14(s[i+12]) for i in range(4)]

    def addRoundKey (self,subkey,state):
        """AddRoundKey transformation"""
        return [i^j for i,j in zip(subkey,state)]

    xorLists = addRoundKey

    def rotWord(self,number):
        """Rotate subkey left"""
        return (((number&0xff000000)>>24) +
                ((number&0xff0000)<<8) +
                ((number&0xff00)<<8) +
                ((number&0xff)<<8))

    def subWord(self,key):
        """Substitute subkeys bytes using S-box"""
        return ((AES.sBox[(key>>24)&0xff]<<24) +
                (AES.sBox[(key>>16)&0xff]<<16) +
                (AES.sBox[(key>>8)&0xff]<<8) +
                 AES.sBox[key&0xff])

    def setKey(self,keySize,key,iv = None):
        """KeyExpansion transformation"""
        rcon = (0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36)
        try:
            assert keySize in AES.keySizeTable
        except AssertionError:
            print("Key size identifier not valid")
            sys.exit("ValueError")
        try:
            assert isinstance(key,int)
        except AssertionError:
            print("Invalid key")
            sys.exit("ValueError")
        klen = len("{:02x}".format(key))//2
        try:
            assert klen <= AES.keySizeTable[keySize]
        except AssertionError:
            print("Key size mismatch")
            sys.exit("ValueError")
        try:
            assert ((self.cipherMode == "MODE_CBC" and isinstance(iv,int)) or
                     self.cipherMode == "MODE_ECB")
        except AssertionError:
                print("IV is mandatory for CBC mode")
                sys.exit(ValueError)

        if self.cipherMode == "MODE_CBC":
            temp = self.intToList(iv)
            self.ivEncrypt = copy(temp)
            self.ivDecrypt = copy(temp)
        nr = AES.numberOfRoundsTable[keySize]
        self.numberOfRounds = nr
        self.wordSize = AES.wordSizeTable[keySize]
        if nr == 10:
            nk = 4
            keyList = self.intToList(key)
        elif nr == 12:
            nk = 6
            keyList =  self.intToList(key>>64) + \
                      (self.intToList(key&int("ff"*32,16)))[8:]
        else:
            nk = 8
            keyList =  self.intToList(key>>128) + \
                       self.intToList(key&int("ff"*64,16))
        for index in range(nk):
            self.w[index] =  (keyList[4*index]<<24) + \
                             (keyList[4*index+1]<<16) + \
                             (keyList[4*index+2]<<8) +\
                              keyList[4*index+3]
        for index in range(nk,self.wordSize):
            temp = self.w[index - 1]
            if index % nk == 0:
                temp = (self.subWord(self.rotWord(temp)) ^
                        rcon[index//nk]<<24)
            elif self.numberOfRounds == 14 and index%nk == 4:
                temp = self.subWord(temp)
            self.w[index] = self.w[index-nk]^temp
        self.keyDefined = True
        return

    def getKey(self,operation):
        """Return next round subkey for encryption or decryption"""
        if operation == "encryption":
            for i in range(0,self.wordSize,4):
                yield self.wordToState(self.w[i:i+4])
        else: # operation = "decryption":
            for i in reversed(range(0,self.wordSize,4)):
                yield self.wordToState(self.w[i:i+4])

    def encryptBlock(self,plaintextBlock):
        """Encrypt a 16-byte block with key already defined"""
        key = self.getKey("encryption")
        state = self.listToState(plaintextBlock)
        state = self.addRoundKey(next(key),state)
        for _ in repeat(None,self.numberOfRounds - 1):
            state = self.subBytes(state)
            state = self.shiftRows(state)
            state = self.mixColumns(state)
            state = self.addRoundKey(next(key),state)
        state = self.subBytes(state)
        state = self.shiftRows(state)
        state = self.addRoundKey(next(key),state)
        return self.stateToList(state)

    def decryptBlock(self,ciphertextBlock):
        """Decrypt a 16-byte block with key already defined"""
        key = self.getKey("decryption")
        state = self.listToState(ciphertextBlock)
        state = self.addRoundKey(next(key),state)
        for _ in repeat(None,self.numberOfRounds - 1):
            state = self.invShiftRows(state)
            state = self.invSubBytes(state)
            state = self.addRoundKey(next(key),state)
            state = self.invMixColumns(state)
        state = self.invShiftRows(state)
        state = self.invSubBytes(state)
        state = self.addRoundKey(next(key),state)
        return self.stateToList(state)

    def padData(self,data):
        """Add PKCS5 padding to plaintext (or just add bytes to fill a block)"""
        paddingLength = 16-(len(data)%16)
        if self.padding == "NoPadding":
            paddingLength %= 16
        if type(data) is bytes:
            return data+bytes(list([paddingLength]*paddingLength))
        else:
            return [ord(s) for s in data]+[paddingLength]*paddingLength

    def unpadData(self,byteList):
        """Remove PKCS5 padding (if present) from plaintext"""
        if self.padding == "PKCS5Padding":
            return "".join(chr(e) for e in byteList[:-byteList[-1]])
        else:
            return "".join(chr(e) for e in byteList)

    def encrypt(self,input):
        """Encrypt plaintext passed as a string or as an integer"""
        try:
            assert self.keyDefined
        except AssertionError:
            print("Key not defined")
            sys.exit("ValueError")

        if type(input) is int:
            inList = self.intToList2(input)
        else:
            inList = self.padData(input)
        outList = []
        if self.cipherMode == "MODE_CBC":
            outBlock = self.ivEncrypt
            for i in range(0,len(inList),16):
                auxList = self.xorLists(outBlock,inList[i:i+16])
                outBlock = self.encryptBlock(auxList)
                outList += outBlock
            self.ivEncrypt = outBlock
        else:
            for i in range(0,len(inList),16):
                outList += self.encryptBlock(inList[i:i+16])
        if type(input) is int:
            return self.listToInt(outList)
        else:
            return outList

    def decrypt(self,input):
        """Decrypt ciphertext passed as a string or as an integer"""
        try:
            assert self.keyDefined
        except AssertionError:
            print("Key not defined")
            sys.exit("ValueError")
        if type(input) is int:
            inList = self.intToList2(input)
        else:
            inList = input
        outList = []
        if self.cipherMode == "MODE_CBC":
            oldInBlock = self.ivDecrypt
            for i in range(0,len(inList),16):
                newInBlock = inList[i:i+16]
                auxList = self.decryptBlock(newInBlock)
                outList += self.xorLists(oldInBlock,auxList)
                oldInBlock = newInBlock
            self.ivDecrypt = oldInBlock
        else:
            for i in range(0,len(inList),16):
                outList += self.decryptBlock(inList[i:i+16])
        if type(input) is int:
            return self.listToInt(outList)
        else:
            return self.unpadData(outList)