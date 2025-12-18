#!/usr/bin/env python3
#
# Author: Joao H de A Franco (jhafranco@gmail.com)
#
# Description: RC4 Python implementation validation
#
# Date: 2012-01-15
#
# License: Attribution-NonCommercial-ShareAlike 3.0 Unported
#          (CC BY-NC-SA 3.0)
#===========================================================

import sys
import RC4
 
def main():
    """Verify the correctness of RC4 implementation using Wikipedia
       test vectors"""
 
    def intToList(inputNumber):
        """Convert a number into a byte list"""
        inputString = "{:02x}".format(inputNumber)
        return [int(inputString[i:i + 2], 16) for i in range(0, len(inputString), 2)]
 
    def string_to_list(inputString):
        """Convert a string into a byte list"""
        return [ord(c) for c in inputString]
 
    def test(key, plaintext, ciphertext, testNumber):
        success = True
        RC4.setKey(string_to_list(key))
        try:
            assert RC4.encrypt(plaintext) == intToList(ciphertext)
            print("RC4 encryption test #{:d} ok!".format(testNumber))
        except AssertionError:
            print("RC4 encryption test #{:d} failed".format(testNumber))
            success = False
        RC4.setKey(string_to_list(key))
        try:
            assert RC4.decrypt(intToList(ciphertext)) == plaintext
            print("RC4 decryption test #{:d} ok!".format(testNumber))
        except AssertionError:
            print("RC4 decryption test #{:d} failed".format(testNumber))
            success = False
        return success
 
    # Test vectors definition section
    numberOfTests = 3
    testVectorList = [{}] * numberOfTests
 
    # Wikipedia test vector #1
    testVectorList[0] = dict(key = "Key",
                             plaintext = "Plaintext",
                             ciphertext = 0xBBF316E8D940AF0AD3,
                             testNumber = 1)
 
    # Wikipedia test vector #2
    testVectorList[1] = dict(key = "Wiki",
                             plaintext = "pedia",
                             ciphertext = 0x1021BF0420,
                             testNumber = 2)
 
    # Wikipedia test vector #3
    testVectorList[2] = dict(key = "Secret",
                             plaintext = "Attack at dawn",
                             ciphertext = 0x45A01F645FC35B383552544B9BF5,
                             testNumber = 3)
 
    # Testing section
    testSuccess = True
    for p in range(numberOfTests):
        testSuccess &= test(**testVectorList[p])
    if testSuccess:
        print("All RC4 tests succeeded!")
    else:
        print("At least one RC4 test failed")
        sys.exit(1)
    sys.exit()
 
if __name__ == '__main__':
    main()