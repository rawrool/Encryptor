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
from cryptography.hazmat.primitives import padding


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
            # dictionary to be stored in json
            secretInfo = {}
            # converts bytes to non-bytes, so they can be stored on json
            secretInfo["key"] = base64.b64encode(Key).decode('utf-8')
            secretInfo["ciphertext"] = base64.b64encode(C).decode('utf-8')
            secretInfo["IV"] = base64.b64encode(IV).decode('utf-8')
            secretInfo["file_extension"] = file_ext
            # dump the data from json onto the created file
            json.dump(secretInfo, encryptedFile)
            # close all opened files
            encryptedFile.close()
            file.close()
            # prints newly created encrypted file's name
            print("New file saved as "+newName)
        # removes original file
        os.remove(filepath)
    else:
        print("File not found, no encryption executed")


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
    if os.path.isfile(filepath):
        try:
            # reads the file
            jread = open(filepath, 'r')
            # loads all the json content
            jsonContent = json.load(jread)
            # decodes all json data into their variables
            IV = base64.b64decode(jsonContent["IV"])
            C = base64.b64decode(jsonContent["ciphertext"])
            Key = base64.b64decode(jsonContent["key"])
            file_ext = jsonContent["file_extension"]
            # initializes the unpadder
            unpadder = padding.PKCS7(constants.PADDING_SIZE).unpadder()
            # separates the filename from the extension
            filename, file_extension = os.path.splitext(filepath)
            # original filename and original file extension
            originalFile = filename+file_ext
            # get decrypted plaintext
            decryptedPT = Mydecrypt(Key, IV, C)
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
            jread.close()
            replace.close()
            # removes encrypted file
            os.remove(filepath)
         except:
            jread.close()
            print("File was never encrypted, no decryption executed")
     else:
        print("File not found, no decryption executed")

