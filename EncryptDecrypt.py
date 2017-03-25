import json
import sys
import pem
import os
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend


path_to_private = "C:/Users/Ryan/Desktop/private_key.pem"
path_to_public = "C:/Users/Ryan/Desktop/public_key.pem"
backend = default_backend()


def encrypt(message):

    # excessive print statements
    print("\nOriginal message: ")
    print(message)

    # generating necessary keys and IV
    aes_key = os.urandom(32)
    hmac_key = os.urandom(32)
    iv = os.urandom(16)
    print("\nKeys: ")
    print(aes_key)
    print(hmac_key)
    print(iv)

    # prepping the padder and encryptor
    padder = padding.PKCS7(128).padder()
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()

    # padding the message with PKCS7
    padded_message = padder.update(message.encode()) + padder.finalize()
    print("\nPadded message: ")
    print(padded_message)

    # encrypting the padded message with AES
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()
    print("\nCiphertext: ")
    print(ciphertext)

    # generating the HMAC tag from ciphertext
    tag = hmac.new(hmac_key, ciphertext, digestmod=hashlib.sha256).digest()
    print("\nHMAC tag: ")
    print(tag)

    # concatenating AES and HMAC keys and IV
    keys = aes_key + hmac_key + iv

    this_will_be_a_json = [ciphertext, keys, tag]
    return this_will_be_a_json


def decrypt(text_and_keys):

    # separating the AES and HMAC keys and IV back out
    aes_key = text_and_keys[1][0:32]
    hmac_key = text_and_keys[1][32:64]
    iv = text_and_keys[1][64:80]
    print("\nKeys again: ")
    print(aes_key)
    print(hmac_key)
    print(iv)

    # generating the HMAC tag from ciphertext
    tag2 = hmac.new(hmac_key, text_and_keys[0], digestmod=hashlib.sha256).digest()
    print("\nHMAC tag: ")
    print(tag2)

    # comparing the two tags
    print("\nTags equal?")
    print(hmac.compare_digest(text_and_keys[2], tag2))

    # prepping decryptor and depadder
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(text_and_keys[0]) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    print("\nPlaintext: ")
    print(plaintext.decode())
    return

private_key = pem.parse_file(path_to_private)
public_key = pem.parse_file(path_to_public)

print("\n-----------------------------")
print("Encrypting")
print("-----------------------------")
imaginary_json = encrypt("A message to be encrypted.")

print("\n-----------------------------")
print("Decrypting")
print("-----------------------------")
decrypt(imaginary_json)
