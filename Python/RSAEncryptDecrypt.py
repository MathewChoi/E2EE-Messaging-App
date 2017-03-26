from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend


# paths to public and private RSA keys
path_to_public = "C:/Users/Ryan/Desktop/public_key.pem"
path_to_private = "C:/Users/Ryan/Desktop/private_key.pem"


def rsa_encrypt(plaintext):

    # reading the public key
    with open(path_to_public, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

    # encrypting the plaintext
    encrypted_text = public_key.encrypt(
        plaintext,
        padding.OAEP(
            # QUESTION FOR MEHRDAD
            # What hash should we use here? Does it matter?
            # I know we shouldn't be using SHA1 anymore, should we just use SHA256 again?
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )

    return encrypted_text


def rsa_decrypt(ciphertext):

    # reading the private key
    with open(path_to_private, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

    # decrypting the ciphertext
    decrypted_text = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )

    return decrypted_text

