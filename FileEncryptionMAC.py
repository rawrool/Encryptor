# -*- coding: utf-8 -*-

"""
Team: Sleeper Reapers
Members: Anthony & Raul
"""

import os
import json
import base64
import cryptography

import constants

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, serialization, hashes, hmac
import cryptography.hazmat.primitives.asymmetric as asymm
from cryptography.hazmat.primitives.asymmetric import rsa


def MyencryptMAC(message, EncKey, HMACKey):
    if len(EncKey) < constants.REQ_KEY_BYTES:
        return "Error: key length was less than the required bytes"
    else:
        # initialize the padder
        padder = padding.PKCS7(constants.PADDING_SIZE).padder()
        # update message with padding
        message = padder.update(message) + padder.finalize()

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
        # initialize the unpadder
        unpadder = padding.PKCS7(constants.PADDING_SIZE).unpadder()
        # update plaintext with unpadding
        plaintext = unpadder.update(plaintext) + unpadder.finalize()
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

        C, IV, tag = MyencryptMAC(fileToString, EncKey, HMACKey)

        # closes file
        file.close()

    return C, IV, EncKey, ext, HMACKey, tag


def MyfileDecryptMAC(C, IV, EncKey, fileName, ext, HMACKey, tag):
    # decrypt to get message
    contents = MydecryptMAC(C, IV, EncKey, HMACKey, tag)
    # store decoded string
    decodedContents = base64.b64decode(contents)
    # separates the filename from the extension
    originalFileName, encFileExt = os.path.splitext(fileName)
    # decrypted file name and ext
    decFile = originalFileName + ext
    # store message onto decrypted file
    with open(decFile, 'wb') as file:
        # write to file
        file.write(decodedContents)
        # close file
        file.close()


def MyRSAEncrypt(filepath, RSA_Publickey_filepath):
    # file encrypt MAC on the filepath
    C, IV, EncKey, ext, HMACKey, tag = MyfileEncryptMAC(filepath)
    # open RSA public key
    with open(RSA_Publickey_filepath, "rb") as publicKey_file:
        public_key = serialization.load_pem_public_key(
            publicKey_file.read(),
            backend=default_backend()
        )
    # RSA encrypt
    RSACipher = public_key.encrypt(
        EncKey + HMACKey,
        asymm.padding.OAEP(
            mgf=asymm.padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return RSACipher, C, IV, tag, ext   # changed tag and ext with each other


def MyRSADecrypt(RSACipher, C, IV, filepath, ext, RSA_Privatekey_filepath, tag):
    # open RSA private key
    with open(RSA_Privatekey_filepath, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    # RSA decrypt
    key = private_key.decrypt(
        RSACipher,
        asymm.padding.OAEP(
            mgf=asymm.padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # unconcatenate the keys
    EncKey = key[0:constants.KEY_LENGTH]
    HMACKey = key[len(EncKey):]
    # file decrypt MAC
    MyfileDecryptMAC(C, IV, EncKey, filepath, ext, HMACKey, tag)


def keyGenerator():
    # creates a folder directory to store keys
    os.mkdir("keyFolder")
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
    with open("keyFolder" + "\\" + "private_key.pem", 'wb') as privateFile:
        privateFile.write(serialPrivateKey)     # writes private key onto file
    # creates a pem file for public key
    with open("keyFolder" + "\\" + "public_key.pem", 'wb') as publicFile:
        publicFile.write(serialPublicKey)   # writes public key onto file

    # closes both files
    privateFile.close()
    publicFile.close()


def dirEncryptor():
    # current work directory
    dirPath = os.path.dirname(os.path.realpath(__file__))
    # gets file list of cwd
    files = os.listdir(dirPath)

    # if the folder with the keys currently doesn't exist
    if "keyFolder" not in files:
        # generate key folder with keys
        keyGenerator()

    # iterate through the files and RSAEncrypt each one
    for fileName in files:
        originalFileName, encFileExt = os.path.splitext(fileName)
        if fileName != "keyFolder" and encFileExt != ".py" and encFileExt != ".dll" and encFileExt != ".manifest" and encFileExt != ".zip" and encFileExt != ".exe" and encFileExt != ".spec" and fileName != "cryptography-1.5-py3.5.egg-info" and fileName != "Include" and fileName != "PyQt5" and fileName != "lib2to3":
            # RSAEncrypt each file
            RSACipher, C, IV, tag, ext = MyRSAEncrypt(fileName, "keyFolder/public_key.pem")

            # get file's name
            fname = os.path.splitext(str(fileName))[0]

            # creates json file
            jsonFile = open(fname + '.json', 'w')

            # dictionary to store in json
            secretInfo = {}

            # converts bytes to non-bytes, so they can be stored on json
            secretInfo["RSACipher"] = base64.b64encode(RSACipher).decode('utf-8')
            secretInfo["ciphertext"] = base64.b64encode(C).decode('utf-8')
            secretInfo["IV"] = base64.b64encode(IV).decode('utf-8')
            secretInfo["tag"] = base64.b64encode(tag).decode('utf-8')
            secretInfo["file_extension"] = ext

            # dump the data from json onto the created file
            json.dump(secretInfo, jsonFile)
            print(fileName+" has been encrypted and stored as "+fname+".json")
            # remove original files
            os.remove(fileName)
    print("Directory encryption was successful!")



def dirDecryptor():
    # current work directory
    dirPath = os.path.dirname(os.path.realpath(__file__))
    # gets file list of cwd
    files = os.listdir(dirPath)
    # if the folder with the keys currently doesn't exist
    if "keyFolder" not in files:
        # nothing else possible to decrypt
        print("You've lost the keys!")
    # else continue decrypting
    else:
        for fileName in files:
            originalFileName, encFileExt = os.path.splitext(fileName)
            if fileName != "keyFolder" and encFileExt != ".py" and encFileExt != ".dll" and encFileExt != ".manifest" and encFileExt != ".zip" and encFileExt != ".exe" and encFileExt != ".spec" and fileName != "cryptography-1.5-py3.5.egg-info" and fileName != "Include" and fileName != "PyQt5" and fileName != "lib2to3":
                # reads the file
                jread = open(fileName, 'r')
                # loads all the json content
                jsonContent = json.load(jread)

                # decodes all json data into their variables
                RSACipher = base64.b64decode(jsonContent["RSACipher"])
                C = base64.b64decode(jsonContent["ciphertext"])
                IV = base64.b64decode(jsonContent["IV"])
                tag = base64.b64decode(jsonContent["tag"])
                ext = jsonContent["file_extension"]

                # RSADecrypt the json data
                MyRSADecrypt(RSACipher, C, IV, fileName, ext, "keyFolder/private_key.pem", tag)

                # close json file
                fname = os.path.splitext(str(fileName))[0]
                jread.close()
                print(fileName+" was decrypted and restored back to "+fname+""+ext)
                # remove json files
                os.remove(fileName)
    print("Directory decryption was successful!")