#!/usr/bin/env python3
#
# Author: Joao H de A Franco (jhafranco@gmail.com)
#
# Description: Implementation of AES_CFB8 and AES_CFB128
#              implementation modes in Python
#
# Date: 2013-06-05
#
# Repository: https://github.com/jhafranco/Crypto
#
# License: Attribution-NonCommercial-ShareAlike 3.0 Unported
#          (CC BY-NC-SA 3.0)
#===========================================================
 
import sys
from functools import reduce
import AES
 
# Auxiliary functions
 
def xor(x,y):
    """Returns the xor between two lists"""
    return bytes(i^j for i,j in zip(x,y))
 
def bytesToInt(b):
    """Converts a bytes string into an integer"""
    return listToInt(list(b))
 
def listToInt(lst):
    """Convert a byte list into a number"""
    return reduce(lambda x,y:(x<<8)+y,lst)
 
def intToList(number):
    """Converts an integer into an integer list"""
    if number == 0:
        return [0]
    lst = []
    while number:
        lst += [number&0xff]
        number >>= 8
    return lst[::-1]
 
def intToBytes(number):
    """Converts an integer into a bytes list"""
    return bytes(intToList(number))
 
def intToList2(number,length=None):
    """Converts an integer into an integer list with
       16, 24 or 32 elements"""
    lst = []
    while number:
        lst.append(number&0xff)
        number >>= 8
    L = len(lst)
    if length:
        pZero = length-L
        assert pZero >= 0
    else:
        if L <= 16:
            pZero = 16-L
        elif L <= 24:
            pZero = 24-L
        elif L <= 32:
            pZero = 32-L
        else:
            raise ValueError
    return list(bytes(pZero)) + lst[::-1]
 
def intToBytes2(number,length=None):
    """Converts an integer into a bytes list with
       16, 24 or 32 elements"""
    return bytes(intToList2(number,length))
 
# Real crypto stuff starts here...
 
def encryptCFB8(keysize,key,iv,input):
    """Encrypts single bytes of input block (CFB8 mode)"""
    inputBuffer = intToBytes2(iv)
    if type(input) is int:
        ptext = intToBytes(input)
    else:
        ptext = bytes(map(ord,input))
    obj = AES.AES("MODE_ECB")
    obj.setKey(keysize,key,iv)    
    ctext = bytes()
    for i in range(0,len(ptext),1):
        AESoutput = obj.encrypt(inputBuffer)
        cbyte = bytes([AESoutput[0] ^ ptext[i]])
        inputBuffer = inputBuffer[1:] + cbyte
        ctext += cbyte
    if type(input) is int:
        ctext = bytesToInt(ctext)
    else:
        ctext = list(ctext)
    return ctext
 
def decryptCFB8(keysize,key,iv,input):
    """Decrypts single bytes of input block (CFB8 mode)"""
    inputBuffer = intToBytes2(iv)
    if type(input) is int:
        ctext = intToBytes(input)
    else:
        ctext = bytes(map(ord,input))
    obj = AES.AES("MODE_ECB")
    obj.setKey(keysize,key,iv) 
    ptext = bytes()
    for i in range(0,len(ctext),1):
        AESoutput = obj.encrypt(inputBuffer)
        pbyte = bytes([AESoutput[0] ^ ctext[i]])
        inputBuffer = inputBuffer[1:] + bytes(ctext[i])
        ptext += pbyte
    if type(input) is int:
        ptext = bytesToInt(ptext)
    else:
        ptext = "".join(chr(e) for e in ptext)
    return ptext
 
# ... and goes on here
 
def encryptCFB128(keysize,key,iv,input):
    """Encrypts a 16-byte input block (CFB128 mode)"""
    inputBuffer = intToBytes2(iv)
    if type(input) is int:
        ptext = intToList2(input)
    else:
        ptext = list(map(ord,input))
        L = 16-len(ptext)
        ptext = list(bytes(L)) + ptext
    obj = AES.AES("MODE_ECB")
    obj.setKey(keysize,key,iv)    
    ctext = bytes()
    L3 = len(ptext)
    for i in range(0,L3,16):
        AESoutput = obj.encrypt(inputBuffer)
        inputBuffer = xor(AESoutput,ptext[i:min(L3,i+16)])
        ctext += bytes(inputBuffer)
    if type(input) is int:
        ctext = bytesToInt(ctext)
    else:
        ctext = list(ctext)
    return ctext
 
def decryptCFB128(keysize,key,iv,input):
    """Decrypts a 16-byte input block (CFB128 mode)"""
    inputBuffer = intToBytes2(iv)
    if type(input) is int:
        ctext = intToList2(input)
    else:
        ctext = list(map(ord,input))
        L = 16-len(ctext)
        ctext = list(bytes(L)) + ctext
    obj = AES.AES("MODE_ECB")
    obj.setKey(keysize,key,iv) 
    ptext = bytes()
    L3 = len(ctext)
    for i in range(0,L3,16):
        AESoutput = obj.encrypt(inputBuffer)
        inputBuffer = ctext[i:min(L3,i+16)]
        ptextBlock = xor(AESoutput,inputBuffer)
        ptext += ptextBlock
    if type(input) is int:
        ptext = bytesToInt(ptext)
    else:
        ptext = "".join(chr(e) for e in ptext)
    return ptext