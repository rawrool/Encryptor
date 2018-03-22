# -*- coding: utf-8 -*-
"""
Created on Thu Mar 15 12:57:55 2018

@author: Anthony
"""

import FileEncryptionV2

choice = 'X'

while choice != 'C' and choice != 'c':
    print("MENU")
    print("A - Encrypt a file")
    print("B - Decrypt a file")
    print("C - Exit program")
    choice = input("Enter an option: ")
    if choice == 'A' or choice == 'a':
        encryptFile = input("Enter the name of the file that you want to encrypt: ")
        publicKey = input("Enter the name of the public key (.pem) file: ")
        FileEncryptionV2.MyRSAEncrypt(encryptFile, publicKey)
    if choice == 'B' or choice == 'b':
        decryptFile = input("Enter the name of the file that you want to decrypt: ")
        privateKey = input("Enter the name of the private key (.pem) file: ")
        FileEncryptionV2.MyRSADecrypt(decryptFile, privateKey)
    if choice == 'C' or choice == 'c':
        print("")
        print("Have a nice day :D")
    else:
        print("")
        print("Invalid option - "+choice)