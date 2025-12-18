#!/usr/bin/env python3
#
# Author: Joao H de A Franco (jhafranco@gmail.com)
#
# Description: Validation of an AES implementation in Python
#
# Date: 2013-06-02
#
# License: Attribution-NonCommercial-ShareAlike 3.0 Unported
#          (CC BY-NC-SA 3.0)
#===========================================================

import os,sys,re
from glob import glob
import AES

# Global counters
noFilesTested = noFilesSkipped = 0
counterOK = counterNOK = 0

class AEStester:
    """"""
    def buildTestCases(self,filename):
        """Build test cases described in a given file"""
        global noFilesTested,noFilesSkipped

        self.basename = os.path.basename(filename)
        if self.basename.startswith('ECB'):
            self.mode = "MODE_ECB"
            noFilesTested += 1
        elif self.basename.startswith('CBC'):
            self.mode = "MODE_CBC"
            noFilesTested += 1
        else:
            noFilesSkipped += 1
            return

        digits = re.search(r"\d{3}",self.basename)
        self.keysize = 'SIZE_' + digits.group()
        result = re.search(r"CFB\d*(\D{6,})\d{3}",self.basename)
        if result != None:
            self.typeTest = result.group(1)
        self.typeTest = re.search(r"\w{3}(\D{6,})\d{3}", self.basename).group(1)
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

        obj = AES.AES(self.mode)
        obj.setKey(self.keysize,self.key,self.iv)
        if self.operation == 'encrypt':
            CIPHERTEXT = obj.encrypt(self.plaintext)
            try:
                assert self.ciphertext == CIPHERTEXT
                counterOK += 1
                printTestCase("OK")
            except AssertionError:
                counterNOK +=1
                print(self.basename)
                printTestCase("failed")
                print("Expected ciphertext={0:0x}".format(self.ciphertext))
                print("Returned ciphertext={0:0x}".format(CIPHERTEXT))
        else:
            PLAINTEXT = obj.decrypt(self.ciphertext)
            try:
                assert self.plaintext == PLAINTEXT
                counterOK += 1
                printTestCase("OK")
            except AssertionError:
                counterNOK +=1
                print(self.basename)
                printTestCase("failed")
                print("Expected plaintext={0:0x}".format(self.plaintext))
                print("Returned plaintext={0:0x}".format(PLAINTEXT))

# Main program
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