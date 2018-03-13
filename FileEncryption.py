"""
Team: Sleeper Reapers
Members: Anthony & Raul
"""

import os
import json
import base64
#import constants

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)
from cryptography.hazmat.primitives import padding

REQ_KEY_BYTES = 32
IV_LENGTH = 16
KEY_LENGTH = 32
PADDING_SIZE = 256

def Myencrypt(message, key):
    if len(key) < REQ_KEY_BYTES:
        return "Error: key length was less than the required bytes"
    else:
        # Generate a random IV of IV_LENGTH.
        IV = os.urandom(IV_LENGTH)
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
    # reads file as bytes
    with open(filepath, "rb") as file:
        # reads the file as a string and stored in fileToString
        fileToString = base64.b64encode(file.read())
        # initializes the padder
        padder = padding.PKCS7(PADDING_SIZE).padder()
        # pads the string
        paddedString = padder.update(fileToString)
        # generates a random Key of KEY_LENGTH
        Key = os.urandom(KEY_LENGTH)
        # uses module to generate C and IV
        C, IV = Myencrypt(paddedString, Key)
        # splits the filepath to get the seperate filename and file_ext
        filename, file_ext = os.path.splitext(filepath)
        # prints successful statement
        print("File was successfully encrypted.")
        f = open(filepath, 'w')
        secretInfo = {}
        secretInfo["key"] = base64.b64encode(Key).decode('utf-8')
        secretInfo["ciphertext"] = base64.b64encode(C).decode('utf-8')
        secretInfo["file_extension"] = file_ext
        secretInfo["IV"] = base64.b64encode(IV).decode('utf-8')
        
        json.dump(secretInfo, f)
        f.close()
        # returns C, IV, Key, file_ext
        return C, IV, Key, file_ext


def Mydecrypt(filename):
    jread = open(filename, 'r')
    jsonContent = json.load(jread)
    jread.close()
    IV = base64.b64decode(jsonContent["IV"])
    C = base64.b64decode(jsonContent["ciphertext"])
    Key =  base64.b64decode(jsonContent["key"])
    file_ext =  jsonContent["file_extension"]
    # Construct a Cipher object, with the key, iv, and additionally the
    # GCM tag used for authenticating the message.
    decryptor = Cipher(
        algorithms.AES(Key),
        modes.CBC(IV),
        backend=default_backend()
    ).decryptor()
    fileN, file_extension = os.path.splitext(filename)
    originalFile = fileN+file_ext
    replace = open(originalFile, "wb")
    replace.write(decryptor.update(C) + decryptor.finalize())
    replace.close()
    # Decryption gets us the authenticated plaintext.
    # If the tag does not match an InvalidTag exception will be raised.
    #return decryptor.update(C) + decryptor.finalize()



