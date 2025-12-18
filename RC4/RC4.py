#!/usr/bin/env python3
#
# Author: Joao H de A Franco (jhafranco@gmail.com)
#
# Description: RC4 implementation in Python 3
#
# Date: 2012-01-15
#
# License: Attribution-NonCommercial-ShareAlike 3.0 Unported
#          (CC BY-NC-SA 3.0)
#===========================================================
 
# Global variables
state = [None] * 256
p = q = None
 
def setKey(key):
    """RC4 Key Scheduling Algorithm (KSA)"""
    global p, q, state
    state = [n for n in range(256)]
    p = q = j = 0
    for i in range(256):
        if len(key) > 0:
            j = (j + state[i] + key[i % len(key)]) % 256
        else:
            j = (j + state[i]) % 256
        state[i], state[j] = state[j], state[i]
 
def byteGenerator():
    """RC4 Pseudo-Random Generation Algorithm (PRGA)"""
    global p, q, state
    p = (p + 1) % 256
    q = (q + state[p]) % 256
    state[p], state[q] = state[q], state[p]
    return state[(state[p] + state[q]) % 256]
 
def encrypt(inputString):
    """Encrypt input string returning a byte list"""
    return [ord(p) ^ byteGenerator() for p in inputString]
 
def decrypt(inputByteList):
    """Decrypt input byte list returning a string"""
    return "".join([chr(c ^ byteGenerator()) for c in inputByteList])
