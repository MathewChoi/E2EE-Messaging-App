from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend
import smtplib
from email.mime.text import MIMEText
import sys


# Constants for logging in to gmail with SMTP
SMTP_GMAIL = 'smtp.gmail.com'
SMTP_PORT = 465
# Constants for logging in to the account to send the emails
SENDER_EMAIL = "ohchitichatmyself@gmail.com"
PASSWORD = "ilovemehrdad"


# Encrypts the given message with the given public key
def rsa_encrypt(plaintext, public_key):
    encrypted_text = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_text


# Decrypts the given ciphertext with the given private key
def rsa_decrypt(ciphertext, private_key):
    decrypted_text = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_text


# Generates a new private key
def generate_private_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private_key


# Returns the public key for the given private key
def get_public_key(private_key):
    public_key = private_key.public_key()
    return public_key


# Emails the corresponding public key for the given private key
def send_public_key(private_key, email):
    public_key = private_key.public_key()

    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    pem = pem.decode()

    # prepping the message to be sent by filling in the body, subject, sender, and recipient
    msg = MIMEText(pem)
    msg['Subject'] = 'Public Key'
    msg['From'] = SENDER_EMAIL
    msg['To'] = email

    server = smtplib.SMTP_SSL(SMTP_GMAIL, SMTP_PORT)
    server.login(SENDER_EMAIL, PASSWORD)

    server.send_message(msg)
    server.quit()


# Gets the key back into the correct format after being copy/pasted by the user from their email
def get_key_input():
    print("Paste the key from the email and hit enter. Then press Ctrl+D: ")

    user_input = sys.stdin.readlines()
    key = "".join(user_input)
    key = key.encode()

    public_key = serialization.load_pem_public_key(
        key,
        backend=default_backend()
    )
    return public_key


# Tester
'''private_key = generate_private_key()
send_public_key(private_key, "ryanpriehl@gmail.com")

text = "Security is not an afterthought; it starts at design."
text = text.encode()

public_key = get_key_input()
cipher = rsa_encrypt(text, public_key)
print("Ciphertext: ")
print(cipher)

plain = rsa_decrypt(cipher, private_key)
plain = plain.decode()
print("Plaintext: ")
print(plain)'''

