from contacts import get_contacted_users, get_public_keys, get_private_keys, add_contact, create_contacts_list, change_pub_keys, change_priv_keys
from make_requests import auth_user, register_user, refresh_token, send_message, get_messages, get_all_users, constants
from encrypt_decrypt import encrypt, decrypt
from RSAEncryptDecrypt import generate_private_key, get_public_key, send_public_key, get_key_input

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key

import smtplib
import json
import cryptography

"""Menu 1"""
class Registered_User:
    def __init__(self,**kwargs):
        self.username = kwargs["username"]
        self.access_tok = kwargs["access_tok"]
        self.refresh_tok = kwargs["refresh_tok"]
        self.contacted_users = [] # list of usernames
        self.public_keys = {} # format "<username>" : "<public_key_path>"
        self.private_keys = {} # format "<username>" : "<private_key_path>"

    def print(self):
        print(self.__dict__)


def login_register():
    cont = True
    while(cont):
        print("\nDisplaying menu options. To select an option enter the integer without punctuation.")
        print("Select an option:")
        print("1. Login")
        print("2. Register")
        print("3. Exit")

        choice = input()
        if (choice == "1"):
            login()
        elif (choice == "2"):
            register()
        elif (choice == "3"):
            print("Exiting program. Goodbye.\n")
            cont = False
        else:
            print("Invalid input. Please enter 1, 2, or 3.\n")

def login():
    print("You entered '1': Login\n")
    print("Enter username: ")
    username = input()
    print("Enter password: ")
    password = input()
    response = auth_user(constants.url, username, password)
    #print("\nResponse:\n {}".format(response))

    if ("access" in response):
        #get access and refresh tokens from server
        tokens = json.loads(response)
        session_user.username = username
        session_user.access_tok = tokens["access token"]
        session_user.refresh_tok = tokens["refresh token"]
        #session_user.print()

        #read user info from files
        session_user.contacted_users  = get_contacted_users(username)
        session_user.private_keys  = get_private_keys(username)
        session_user.public_keys  = get_public_keys(username)

        #show second menu
        chatroom_menu()
    else:
        print(response)

def register():
    #register information onto server
    print("Enter username: ")
    username = input()
    print("Enter email: ")
    email = input()
    print("Enter password: ")
    password = input()
    response = register_user(constants.url, email, username, password)
    #print("\nResponse:\n {}".format(response))

    if ("Please enter" not in response):
        create_contacts_list(username) #create the contacts list table
        print("Redirecting you to the login menu...")
        login() #go to login menu

def get_username_list():
    response = json.loads(get_all_users(constants.url))
    contact_list = response['all usernames']
    username_list = []
    for contact in contact_list:
        username = contact['username']
        username_list.append(username)
    return username_list

def get_email_list():
    response = json.loads(get_all_users(constants.url))
    contact_list = response['all usernames']
    email_list = []
    for contact in contact_list:
        email = contact['email']
        email_list.append(email)
    return email_list


"""Menu 2"""
def chatroom_menu():
    cont = True
    while(cont):
        print("\nDisplaying menu options. To select an option enter the integer without punctuation.")
        print("Select an option:")
        print("1. Send a message")
        print("2. Get messages")
        print("3. Add received keys")
        print("4. Quit")

        choice = input()
        if (choice == "1"):
            send_msg()
        elif (choice == "2"):
            get_msg()
        elif (choice == "3"):
            add_received_keys()
        elif (choice == "4"):
            print("Exiting program. Goodbye.\n")
            cont = False
        else:
            print("Invalid input. Please enter 1, 2, 3, or 4.\n")

def deserialize_priv_key(priv_key):
    pem = priv_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption())
    pem = pem.decode()
    return pem

def send_msg():
    print("You entered '1': Send a message\n")
    #while input is not -1
    username_list = get_username_list()

    print("\nPlease select the username of the user you would like to communicate with from the following list.")
    print(username_list)
    receiver = input()

    if receiver in username_list:
        print("{} is in {}".format(receiver, username_list))

        if receiver in session_user.contacted_users and session_user.public_keys[receiver] is not None:
            print("\nWhat would you like to send to {}".format(receiver))
            message = input()

            if (len(message) > 0):
                public_key = session_user.public_keys[receiver]
                public_key = load_pem_public_key(public_key, backend=default_backend())
                #public_key = public_key.encode()
                json_object = encrypt(message, public_key)
                response = send_message = send_message(contants.url, session_user.username, receiver, json_object, session_user.access_token)
                print(response)

            else:
                print("Your message must be longer than 0 char long. Please try again")

        else:
            print("You have not communicated with this person. Sending them your public key.")
            #generate key pair
            priv_key = generate_private_key()
            #store private key

            pem  = deserialize_priv_key(priv_key)
            change_priv_keys(session_user.username, receiver, pem)
            session_user.public_keys[receiver] = pem

            email_list = get_email_list()
            print("\nWho do you want to send the public key to? Enter their full email: {}".format(email_list))
            receiver_email = input()
            #receiver_username = sender
            if (receiver_email in email_list):
                send_public_key(priv_key, receiver_email, session_user.username)
                print("\nPrivate key for messages form {} has been updated.".format(receiver))
            else:
                print("\nThat email is not in the system. Try again.")


    else:
        print("That is not a valid registered username. Try again..")

def get_msg():
    print("You entered '2': Get messages\n")
    #get messages and display them
    session_user.access_tok = refresh_token(constants.url, session_user.access_tok)
    messages = get_message(constants.url, session_user.username, session_user.access_tok)
    for message in messages:
        sender = message["sender"]
        json_object = json.loads(message["ciphertext"])
        message = decrypt(json_object, session_user.private_keys[sender].encode())

        print("Message = {}".format(message))

def add_received_keys():
    #get users list
    username_list = get_username_list()
    print("Users in the system: {}".format(username_list))
    print('\nWho sent you the keys?')
    sender = input()
    if (sender in username_list or session_user.public_keys[sender] is None):
        add_contact(session_user.username, sender)
        pub_key = get_key_input()
        change_pub_keys(session_user.username, sender, pub_key)

        session_user.contacted_users.append(sender)
        session_user.public_keys[sender] = pub_key

        #if (session_user.private_keys[sender] is None):
        #generate private key
        priv_key = generate_private_key()

        pem = deserialize_priv_key(priv_key)
        #store private key
        change_priv_keys(session_user.username, sender, pem)
        session_user.private_keys = get_private_keys(session_user.username)
        #send public key
        email_list = get_email_list()
        print("\nWho do you want to send the public key to? Enter their full email: {}".format(email_list))
        receiver = input()
        receiver_username = sender
        if (receiver in email_list):
            send_public_key(priv_key, receiver, sender)
        print("\nPrivate key for {} has been updated.".format(sender))
        print('\nPublic key for {} has been updated'.format(sender))

"""
    Driver
"""
session_user = Registered_User(username=0,access_tok=0,refresh_tok=0)
username_list = get_username_list()

login_register()
