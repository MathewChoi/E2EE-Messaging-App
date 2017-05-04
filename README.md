# 💩 “Oh Chit, I Chat Myself” 💩
An end-to-end encrypted chat application built by Mathew Choi and Ryan Riehl.

---

## Our Philosophy

A great man once said, “Security is not an afterthought; it starts at design”. These life-changing words were taken to heart during the development of this app, and as such every “bit” of it from the ground up has been built to provide security for its users. 

## Security Methodology

![DigitalEnvelope.png](https://github.com/MathewChoi/E2EE-Messaging-App/blob/Picture4Wiki/DigitalEnvelope.png "Digital Envelope")

Fig.1 - Overview of the “digital envelope” process.

### Digital Envelope
This app uses “digital envelopes” when sending messages. Creating the digital envelope is a two-step procedure:
1. Encrypt the message using a symmetric-key algorithm.
2. Encrypt the key used for encrypting the message using an asymmetric-key algorithm.

The ciphertext and the encrypted key can then be shared with the recipient. The recipient uses their asymmetric private-key to decrypt the symmetric key, then uses that key that to finally decrypt the message. The goal of this is to provide confidentiality. The message is encrypted during the entire process so any adversary that somehow gets ahold of it won’t be able to read it. Also, the server is not involved in decrypting the message, nor is it able to, so the message is guaranteed to be kept confidential there as well. The digital envelope provides a way of exchanging the ciphertext and keys such that only the recipient will be able to read the message.

In addition to the encrypted message and keys, a tag is generated based on the ciphertext and is included in the package sent to the recipient. The tag generation also requires a key so that key should be encrypted with the asymmetric algorithm as well and be recovered by the receiver later. The recipient can then generate a new tag from the ciphertext and key they receive and compare it to tag they receive. If the tags match the recipient can be confident that the message they’ve received hasn’t been tampered with. Through this process data integrity is provided to the users.

### Cryptographic Algorithms Used

The following list details the cryptographic algorithms, associated padding methods, and modes of encryption used in the app and how they are used. The app is built on the assumption that these algorithms are secure. In the future as these are broken, become obsolete due to improved computing power, or otherwise are no longer secure they should be updated or the security provided by the app will be lost.
1. AES with a key size of 256-bits is used to encrypt the user’s message. PKCS7 is used to pad the message to the correct block size, then cipher block chaining is used to encrypt the blocks. Cipher Block Chaining is used because it is probabilistic, so a 128-bit initialization vector (IV) is generated and used as well.
2. HMAC with SHA256 is used to generate the integrity tag based on the ciphertext received from AES encrypting the message.
3. RSA is used to encrypt the concatenated AES and HMAC keys and IV. A 2048-bit RSA public/private key pair was generated to this end. OAEP was used for padding to ensure that it is probabilistic with SHA256 used again for the hash function.

### Key Exchange
Before two users can communicate they need to establish the keys they will be using for communication. This must be done before anything can be encrypted and as such is a point of vulnerability. For key exchange, this app requires users to share their key via email to establish the shared secret. If we assume the email channel is secure this isn’t a problem, but that’s not a very reliable assumption (see “Potential Security Improvements for more).

## Implementation
This app is coded entirely in Python. The external resources used are detailed below. There is also a brief overview of each of the python files and their purpose.

### Libraries and Frameworks Used
* [Cryptography Python Library](https://cryptography.io/en/latest/): Provided all of the cryptographic algorithms, padding methods, hash functions, and modes of encryption used in the app.
* [Flask](http://flask.pocoo.org/docs/0.12/) / [Flask-RESTful](https://flask-restful.readthedocs.io/en/0.3.5/): Framework and extension used to develop the API for interacting with the server (sending and receiving messages, logging in, etc).

### Python Files
* app.py: Sets configurations for the app.
* authenticate.py: The Authenticator class is used to authorize users when they try to login and refresh their token.
* create_table.py: Creates tables in database for users and messages if they don’t already exist.
* EncryptDecrypt.py: Contains methods for encrypting and decrypting messages using the digital envelope protocol described above.
* Main.py: The main app driver run to start the app. Contains the basic console menus used to perform different actions.
* make_requests.py: Makes requests to server regarding user login and registration, sending and receiving messages, and refreshing tokens.
* message.py: Class for tracking and managing messages in the database and their properties.
* RSAEncryptDecrypt.py: Contains methods for doing RSA encryption and decryption including reading from public and private key .pem files.
* user.py: Class for keeping track of users and their information, creating new users upon registration, and finding users in the database.

## Potential Security Improvements
While the app in its current state does provide end-to-end encrypted chat and as such a good deal of security, there are still many changes that could be made to improve the security of the app.

### Tokenization
Currently when the user logs in their password is sent as plaintext to the server to be authenticated. While this theoretically isn’t an issue because SSL should protect it en route, it still creates a major vulnerability should SSL fail. This vulnerability could be resolved by implementing tokenization to prevent the password from ever having to leave the local host.

### Password Choice
Currently there are no rules limiting what users can choose as their passwords. Inevitably, this means that there will be people who use short, brute-forceable passwords or common, dictionary-attackable passwords. User convenience should be sacrificed in this area to make the passwords more secure by imposing rules such as minimum password length.

### Password Storage
Currently passwords are stored in the database salted and hashed with SHA512. While this is significantly better than storing the password as plaintext or hashed without salt, it could be improved further by using scrypt instead of hashing.

### Key Exchange
The current method of users establishing their shared secret key via email is a significant vulnerability. Because the email channel is (likely) not encrypted, an adversary that gains access to the email can easily recover the secret key. Also, using email in this manner requires that we trust the company whose email we are using which again goes against the point of end-to-end encryption.

### 2-Step Verification
Because passwords on their own are often not the most secure for a myriad of reasons, 2-step verification should be employed. Especially with some of the password vulnerabilities mentioned above the passwords are a weak point of the app. 2-step verification would reduce the likelihood of someone having an adversary gain access to their account.

## Potential Non-Security Improvements
Given that the goal of the app was to provide an end-to-end encrypted messaging service, priority was given to implementing security features during development. As a result, many features that would improve user convenience and usability were not implemented. Below is a far from comprehensive list of features that don’t directly affect security, but could be implemented to improve the app in other ways.
* Improved GUI
* Group chat
* Improved key exchange


