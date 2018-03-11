# -*- coding: utf-8 -*-
"""
Created on Sat Mar 10 17:01:29 2018

@author: Anthony
"""

import os
import base64

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)
from cryptography.hazmat.primitives import padding

def Myencrypt(message, key):
    if len(key) < 32:
        C = 0
        IV = 0
        print("Error: key length was less than 32 bytes")
    else:    
        # Generate a random 16-byte IV.
        ivLen = 16
        IV = os.urandom(ivLen)
        # Construct an AES-CBC Cipher object with the given key and a
        # randomly generated IV.
        encryptor = Cipher(
            algorithms.AES(key),
            modes.CBC(IV),
            backend=default_backend()
        ).encryptor()
    
        # Encrypt the plaintext and get the associated ciphertext.
        # CBC does not require padding.
        C = encryptor.update(message) + encryptor.finalize()

    return (C, IV)


def MyfileEncrypt(filepath):
    with open(filepath, "rb") as jpgFile:
        fileToString = base64.b64encode(jpgFile.read())
        padder = padding.PKCS7(256).padder()
        paddedString = padder.update(fileToString)
        keyLen = 32
        Key = os.urandom(keyLen)
        C, IV = Myencrypt(paddedString, Key)
        filename, file_extension = os.path.splitext(filepath)
        print("File was successfully encrypted.")
        return C, IV, Key, file_extension

def Mydecrypt(Key, IV, C):
    # Construct a Cipher object, with the key, iv, and additionally the
    # GCM tag used for authenticating the message.
    decryptor = Cipher(
        algorithms.AES(Key),
        modes.CBC(IV),
        backend=default_backend()
    ).decryptor()
    
    # Decryption gets us the authenticated plaintext.
    # If the tag does not match an InvalidTag exception will be raised.
    return decryptor.update(C) + decryptor.finalize()

def saveNewFile(output, File_Name):
    checkEncrypt = open(File_Name, "wb")
    checkEncrypt.write(base64.b64decode(output))
    checkEncrypt.close()

fileName = input("Enter the name of the file you want to encrypt: ")
C, IV, Key, file_extension = MyfileEncrypt(fileName)
newSaveName = input("Enter the name of the new file: ")
saveNewFile(C, newSaveName)
print("Encrypted file was saved as "+newSaveName)
option = input("Do you want to decrypt and save as original file type? (Y/N)")
if option == 'Y' or option == 'y':
    originalFile = Mydecrypt(Key, IV, C)
    filename, old_extension = os.path.splitext(newSaveName)
    newSaveName = filename + file_extension
    saveNewFile(originalFile, newSaveName)
    print("File was resaved with its original format")



