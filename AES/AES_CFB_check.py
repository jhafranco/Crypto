#!/usr/bin/env python3
#
# Author: Joao H de A Franco (jhafranco@gmail.com)
#
# Description: Validation of AES_CFB8 and AES_CFB128
#              implementations in Python
#
# Date: 2013-06-05
#
# Repository: https://github.com/jhafranco/Crypto
#
# License: Attribution-NonCommercial-ShareAlike 3.0 Unported
#          (CC BY-NC-SA 3.0)
#===========================================================
 
import os,sys,re
from glob import glob
import AES_CFB
 
# Global counters
noFilesTested = noFilesSkipped = 0
counterOK = counterNOK = 0
 
class AEStester:
    def buildTestCases(self,filename):
        """Build test cases described in a given file"""
        global noFilesTested,noFilesSkipped
         
        self.basename = os.path.basename(filename)
        if self.basename.startswith('CFB'):
            if self.basename.startswith('CFB8'):
                self.mode = "MODE_CFB8"
                result = re.search(r"CFB8(\D{6,})\d{3}",self.basename)
                self.typeTest = result.group(1)                
            elif self.basename.startswith('CFB128'):
                self.mode = "MODE_CFB128"
                result = re.search(r"CFB128(\D{6,})\d{3}",self.basename)
                self.typeTest = result.group(1)                
            else: # CFB1 files not considered
                noFilesSkipped += 1
                return
        else: # not CFB files
            noFilesSkipped += 1
            return
     
        noFilesTested += 1
        digits = re.search(r"(\d{3})\.",self.basename)
        self.keysize = 'SIZE_' + digits.group(1)
        self.iv = None
        for line in open(filename):
            line = line.strip()
            if (line == "") or line.startswith('#'):
                continue
            elif line == '[ENCRYPT]':
                self.operation = 'encrypt'
                continue
            elif line == '[DECRYPT]':
                self.operation = 'decrypt'
                continue
            param,_,value = line.split(' ',2)
            if param == "COUNT":
                self.count = int(value)
                continue
            else:           
                self.__setattr__(param.lower(),int(value,16))
                if (self.operation == 'encrypt') and (param == "CIPHERTEXT") or \
                   (self.operation == 'decrypt' and param == "PLAINTEXT"):
                    self.runTestCase()
     
    def runTestCase(self):
        """Execute test case and report result"""
        global counterOK,counterNOK      
         
        def printTestCase(result):
            print("Type={0:s} Mode={1:s} Keysize={2:s} Function={3:s} Count={4:03d} {5:s}"\
                  .format(self.typeTest,self.mode[5:],\
                          self.keysize[5:],self.operation.upper(),\
                          self.count,result))              
        if self.operation == 'encrypt':
            if self.mode == "MODE_CFB8":
                CIPHERTEXT = AES_CFB.encryptCFB8(self.keysize,self.key,self.iv,self.plaintext)
            else:
                CIPHERTEXT = AES_CFB.encryptCFB128(self.keysize,self.key,self.iv,self.plaintext)
            try:
                assert self.ciphertext == CIPHERTEXT
                counterOK += 1
                printTestCase("OK")   
            except AssertionError:
                counterNOK +=1
                print(self.basename,end=" ")
                printTestCase("failed")
                print("Expected ciphertext={0:0x}".format(self.ciphertext))
                print("Returned ciphertext={0:0x}".format(CIPHERTEXT))
        else:
            if self.mode == "MODE_CFB8":
                PLAINTEXT = AES_CFB.decryptCFB8(self.keysize,self.key,self.iv,self.ciphertext)
            else:
                PLAINTEXT = AES_CFB.decryptCFB128(self.keysize,self.key,self.iv,self.ciphertext)
            try:
                assert self.plaintext == PLAINTEXT
                counterOK += 1
                printTestCase("OK")
            except AssertionError:
                counterNOK +=1
                print(self.basename,end=" ")
                printTestCase("failed")
                print("Expected plaintext={0:0x}".format(self.plaintext))
                print("Returned plaintext={0:0x}".format(PLAINTEXT))
 
if __name__ == '__main__': 
    path = os.path.dirname(__file__)
    files = sys.argv[1:]
    if not files:
        files = glob(os.path.join(path,'KAT_AES','*.rsp'))
        files.sort()
    for file in files:
        AEStester().buildTestCases(file)
    print("Files tested={0:d}".format(noFilesTested))
    print("Files skipped={0:d}".format(noFilesSkipped))
    print("Test cases OK={0:d}".format(counterOK))
    print("Test cases NOK={0:d}".format(counterNOK))