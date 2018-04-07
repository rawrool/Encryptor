# -*- coding: utf-8 -*-

"""
Team: Sleeper Reapers
Members: Anthony & Raul
"""

import os
import base64
import cryptography
import constants

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes, hmac


def MyencryptMAC(message, EncKey, HMACKey):
    if len(EncKey) < constants.REQ_KEY_BYTES:
        return "Error: key length was less than the required bytes"
    else:
        # Generate a random IV of IV_LENGTH.
        IV = os.urandom(constants.IV_LENGTH)
        # Construct an AES-CBC Cipher object with the given key and a
        # randomly generated IV.
        encryptor = Cipher(
            algorithms.AES(EncKey),
            modes.CBC(IV),
            backend=default_backend()
        ).encryptor()

        # Encrypt the plaintext and get the associated ciphertext.
        C = encryptor.update(message) + encryptor.finalize()

        # Uses a key and hash function to calculate message authentication code
        h = hmac.HMAC(HMACKey, hashes.SHA256(), backend=default_backend())
        h.update(C)
        tag = h.finalize()

        return C, IV, tag


def MydecryptMAC(C, IV, EncKey, HMACKey, tag):
    # try block to check for the integrity of a message
    try:
        # Construct a Cipher object, with the key, iv, and additionally the
        # GCM tag used for authenticating the message.
        decryptor = Cipher(
            algorithms.AES(EncKey),
            modes.CBC(IV),
            backend=default_backend()
        ).decryptor()

        # Decryptor gets us the plaintext.
        plaintext = decryptor.update(C) + decryptor.finalize()
        # If the signatures don't match an exception will be raised.
        h = hmac.HMAC(HMACKey, hashes.SHA256(), backend=default_backend())
        h.update(C)
        h.verify(tag)
        return plaintext
    except cryptography.exceptions.InvalidSignature:
        print("Signature does not match original. Use correct tag.")


def MyfileEncryptMAC(filepath):
    # read file as bytes
    with open(filepath, "rb") as file:
        # generates a random EncKey of KEY_LENGTH
        EncKey = os.urandom(constants.KEY_LENGTH)
        # generates a random HMACKey of KEY_LENGTH
        HMACKey = os.urandom(constants.KEY_LENGTH)

        # splits the filepath to get the separate filename and file ext
        fileName, ext = os.path.splitext(filepath)

        # reads the file as a string and stored in fileToString
        fileToString = base64.b64encode(file.read())

        # initializes the padder
        padder = padding.PKCS7(constants.PADDING_SIZE).padder()
        # pads the string
        paddedString = padder.update(fileToString)

        C, IV, tag = MyencryptMAC(paddedString, EncKey, HMACKey)

        # creates an encrypted file of .lol ext
        newExt = ".lol"
        newName = fileName + newExt
        # creates a file of newExt
        encryptedFile = open(newName, 'w')

        # closes files
        encryptedFile.close()
        file.close()

    # removes original file
    os.remove(filepath)

    return C, IV, EncKey, ext, HMACKey, tag
