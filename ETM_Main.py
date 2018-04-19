# -*- coding: utf-8 -*-
"""
Created on Thu Mar 15 12:57:55 2018

@author: Anthony
"""

import FileEncryptionMAC
import os

choice = 'X'

while choice != 'C' and choice != 'c':
    print("")
    print("MENU")
    print("A - Encrypt files in working directory")
    print("B - Decrypt files in working directory")
    print("C - Exit program")
    #dirPath = os.path.dirname(os.path.realpath(__file__))
    #print(os.listdir(dirPath))
    choice = input("Enter an option: ")
    if choice == 'A' or choice == 'a':
        #encryptFile = input("Enter the name of the file that you want to encrypt: ")
        #publicKey = input("Enter the name of the public key (.pem) file: ")
        #publicKey = "public_key.pem"
        FileEncryptionMAC.dirEncryptor()
    if choice == 'B' or choice == 'b':
        #decryptFile = input("Enter the name of the file that you want to decrypt: ")
        #privateKey = input("Enter the name of the private key (.pem) file: ")
        #privateKey = "private_key.pem"
        FileEncryptionMAC.dirDecryptor()
    if choice == 'C' or choice == 'c':
        print("")
        print("Have a nice day :D")
    if choice !='C' and choice !='c'and choice !='B' and choice !='b' and choice !='A' and choice !='a':
        print("")
        print("Invalid option - "+choice)