"""
Team: Sleeper Reapers
Members: Anthony & Raul
"""

import os
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
        # splits the filepath to get the seperate filename and file_ext
        filename, file_ext = os.path.splitext(filepath)
        # prints successful statement
        print("File was successfully encrypted.")
        # returns C, IV, Key, file_ext
        return C, IV, Key, file_ext


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


# method to generate a new file
def saveNewFile(output, File_Name):
    # creates a file
    checkEncrypt = open(File_Name, "wb")
    # convert/decode the non-bytes from the file
    checkEncrypt.write(base64.b64decode(output))
    checkEncrypt.close()


# stores the file path of the file to encrypt
filePath = input("Enter the file path of the file you want to encrypt: ")
# initializes C, IV, Key, file_ext from calling MyfileEncrypt
C, IV, Key, file_extension = MyfileEncrypt(filePath)
# stores name of new encrypted file
newSaveName = input("Enter the name of the new file: ")
# generates a new encrypted file
saveNewFile(C, newSaveName)
# prints successful message with the new file's name
print("Encrypted file was saved as " + newSaveName)
# gets user's response for wanting to decrypt file
option = input("Do you want to decrypt and save as original file type? (Y/N)")
# decrypts and generates decrypted file if user chooses y/Y
if option == 'Y' or option == 'y':
    originalFile = Mydecrypt(Key, IV, C)
    filename, old_extension = os.path.splitext(newSaveName)
    newSaveName = filename + file_extension
    saveNewFile(originalFile, newSaveName)
    print("File was re-saved with its original format")
else:
    print("Good Bye.")
