import json
import os
import hmac
import hashlib
import RSAEncryptDecrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

backend = default_backend()
AES_KEY_SIZE = 32
HMAC_KEY_SIZE = 32
IV_SIZE = 16
AES_BLOCK_SIZE = 128


def encrypt(message):

    # generating necessary keys and IV
    aes_key = os.urandom(AES_KEY_SIZE)
    hmac_key = os.urandom(HMAC_KEY_SIZE)
    iv = os.urandom(IV_SIZE)
    print("\nKeys: ")
    print(aes_key)
    print(hmac_key)
    print(iv)

    # prepping the padder and AES encryptor
    padder = padding.PKCS7(AES_BLOCK_SIZE).padder()
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
    print(type(tag))

    # concatenating AES key, HMAC key, and IV then RSA encrypting
    keys = aes_key + hmac_key + iv
    encrypted_keys = RSAEncryptDecrypt.rsa_encrypt(keys)

    # packaging and outputting the encrypted message, encrypted keys, and HMAC tag
    # latin1 is used for encoding because json requires a string and latin1 can translate every byte
    data = [ciphertext.decode(encoding='latin1'), encrypted_keys.decode(encoding='latin1'), tag.decode(encoding='latin1')]
    data_string = json.dumps(data)
    json_object = json.loads(data_string)

    return json_object


def decrypt(json_object):

    # extracting from the json and converting back to bytes
    ciphertext = bytes(json_object[0], encoding='latin1')
    encrypted_keys = bytes(json_object[1], encoding='latin1')
    tag = bytes(json_object[2], encoding='latin1')

    # RSA decrypting the keys
    keys = RSAEncryptDecrypt.rsa_decrypt(encrypted_keys)

    # separating the AES and HMAC keys and IV back out
    aes_key = keys[0 : AES_KEY_SIZE]
    hmac_key = keys[AES_KEY_SIZE : AES_KEY_SIZE + HMAC_KEY_SIZE]
    iv = keys[AES_KEY_SIZE + HMAC_KEY_SIZE : AES_KEY_SIZE + HMAC_KEY_SIZE + IV_SIZE]
    print("\nKeys again: ")
    print(aes_key)
    print(hmac_key)
    print(iv)

    # generating the HMAC tag from ciphertext
    tag_check = hmac.new(hmac_key, ciphertext, digestmod=hashlib.sha256).digest()
    print("\nHMAC tag: ")
    print(tag_check)

    # comparing the two tags
    print("\nTags equal?")
    print(hmac.compare_digest(tag, tag_check))

    # decrypting the ciphertext
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # unpadding the plaintext
    unpadder = padding.PKCS7(AES_BLOCK_SIZE).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    plaintext = plaintext.decode()

    return plaintext
