# -*- coding: utf-8 -*-

"""
Team: Sleeper Reapers
Members: Anthony & Raul
"""

import os
import json
import base64
import constants

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)
from cryptography.hazmat.primitives.asymmetric.padding import OAEP
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.padding import MGF1

def Myencrypt(message, key):
    if len(key) < constants.REQ_KEY_BYTES:
        return "Error: key length was less than the required bytes"
    else:
        # Generate a random IV of IV_LENGTH.
        IV = os.urandom(constants.IV_LENGTH)
        # Construct an AES-CBC Cipher object with the given key and a
        # randomly generated IV.
        encryptor = Cipher(
            algorithms.AES(key),
            modes.CBC(IV),
            backend=default_backend()
        ).encryptor()

        # Encrypt the plaintext and get the associated ciphertext.
        C = encryptor.update(message) + encryptor.finalize()
        return C, IV


def MyfileEncrypt(filepath):
    if os.path.isfile(filepath):
        # reads file as bytes
        with open(filepath, "rb") as file:
            # reads the file as a string and stored in fileToString
            fileToString = base64.b64encode(file.read())
            # initializes the padder
            padder = padding.PKCS7(constants.PADDING_SIZE).padder()
            # pads the string
            paddedString = padder.update(fileToString)
            # generates a random Key of KEY_LENGTH
            Key = os.urandom(constants.KEY_LENGTH)
            # uses module to generate C and IV
            C, IV = Myencrypt(paddedString, Key)
            # splits the filepath to get the separate filename and file_ext
            filename, file_ext = os.path.splitext(filepath)
            # prints successful statement
            print("File was successfully encrypted.")
            # creates an extension for encrypted file
            newExt = input("Enter the extension of the new file: ")
            if newExt[0] == '.':
                newName = filename+newExt
            else:
                newName = filename+'.'+newExt
            # creates a file of newExt
            encryptedFile = open(newName, 'w')
            encryptedFile.close()
            file.close()
            # prints newly created encrypted file's name
            print("New file saved as "+newName)
        # removes original file
        os.remove(filepath)
        return (C, IV, Key, newExt)
    else:
        print("File not found, no encryption executed.")

    
        
def MyRSAEncrypt(filepath, RSA_PublicKey_FilePath):
    if os.path.isfile(filepath) and os.path.isfile(RSA_PublicKey_FilePath):
        C, IV, Key, file_ext = MyfileEncrypt(filepath)
        with open(RSA_PublicKey_FilePath, "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
        RSAcipher = public_key.encrypt(
                Key,
             OAEP(
                 mgf= MGF1(algorithm=hashes.SHA256()),
                 algorithm=hashes.SHA256(),
                 label=None
             )
        ) 
        filename, file_extOld = os.path.splitext(filepath)
        newFile = filename + file_ext     
        encryptedFile = open(newFile, 'w')
        # dictionary to be stored in json
        secretInfo = {}
        # converts bytes to non-bytes, so they can be stored on json
        secretInfo["RSAcipher"] = base64.b64encode(RSAcipher).decode('utf-8')
        secretInfo["ciphertext"] = base64.b64encode(C).decode('utf-8')
        secretInfo["IV"] = base64.b64encode(IV).decode('utf-8')
        secretInfo["file_extension"] = file_extOld
        # dump the data from json onto the created file
        json.dump(secretInfo, encryptedFile)
        # close all opened files
        encryptedFile.close()
        key_file.close()
    elif not os.path.isfile(filepath):
        print(filepath+" not found, no encryption executed.")
    elif not os.path.isfile(RSA_PublicKey_FilePath):
        print("Public key not found, no encryption executed.")

    #return RSAcipher, C, IV, file_ext    
    
    


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
    plaintext = decryptor.update(C) + decryptor.finalize()
    return plaintext


def MyfileDecrypt(filepath):
        # original filename and original file extension
    # reads the file
    if(os.path.isfile(filepath)):
        try:
            jread = open(filepath, 'r')
            # loads all the json content
            jsonContent = json.load(jread)
            # decodes all json data into their variables
            IV = base64.b64decode(jsonContent["IV"])
            C = base64.b64decode(jsonContent["ciphertext"])
            RSAcipher = base64.b64decode(jsonContent["RSAcipher"])
            file_ext = jsonContent["file_extension"]
            jread.close()
            return C, RSAcipher, IV, file_ext
        except:
            jread.close()
            print(filepath+" was never encrypted, no decryption executed.")
            file_ext = "error"
            C = 0
            RSAcipher = 0
            IV = 0
            return C, RSAcipher, IV, file_ext
            
    else:
        print(filepath+" was not found, no decryption executed.")
        file_ext = "error"
        C = 0
        RSAcipher = 0
        IV = 0
        return C, RSAcipher, IV, file_ext
        
        
        
        
def MyRSADecrypt(filepath, RSA_PrivateKey_FilePath):
    C, RSAcipher, IV, file_ext = MyfileDecrypt(filepath)
    # separates the filename from the extension
    filename, file_extension = os.path.splitext(filepath)
    originalFile = filename+file_ext
    if C != 0 and os.path.isfile(RSA_PrivateKey_FilePath):
        password = "pass"
        passwordBytes = password.encode('utf-8')
        with open(RSA_PrivateKey_FilePath, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=passwordBytes,
                backend=default_backend()
            )
        Key = private_key.decrypt(
                RSAcipher,
             OAEP(
                 mgf=MGF1(algorithm=hashes.SHA256()),
                 algorithm=hashes.SHA256(),
                 label=None
             )
        )
        # get decrypted plaintext
        decryptedPT = Mydecrypt(Key, IV, C)
        # initializes the unpadder
        unpadder = padding.PKCS7(constants.PADDING_SIZE).unpadder()
        # removes the padding from the plaintext
        unpaddedPT = base64.b64decode(unpadder.update(decryptedPT))
        # recreates file with original name
        replace = open(originalFile, "wb")
        # write original data on recreated file
        replace.write(unpaddedPT)
        # prints successful statements
        print('File was successfully decrypted.')
        print('File restored to '+originalFile)
        # closes all opened files
        replace.close()
        # removes encrypted file
        key_file.close()
        os.remove(filepath)
        #return RSAcipher, C, IV, file_ext
    elif not os.path.isfile(RSA_PrivateKey_FilePath):
        print('Private key not found, no decryption executed.')
