from contacts import get_contacted_users, get_public_keys, get_private_keys, add_contact, create_contacts_list
from make_requests import auth_user, register_user, refresh_token, send_message, get_messages, get_all_users, constants
from pathlib import Path
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

import json
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

    def contacted_user(self, username):
        pass

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
    print("\nResponse:\n {}".format(response))
    if ("access" in response):
        #get access and refresh tokens from server
        tokens = json.loads(response)
        session_user.username = username
        session_user.access_tok = tokens["access token"]
        session_user.refresh_tok = tokens["refresh token"]
        session_user.print()

        #read user info from files
        session_user.contacted_users  = get_contacted_users(username)
        session_user.private_keys  = get_private_keys(username)
        session_user.public_keys  = get_public_keys(username)

        #show second menu
        chatroom_menu()

def register():
    #register information onto server
    print("Enter username: ")
    username = input()
    print("Enter email: ")
    email = input()
    print("Enter password: ")
    password = input()
    response = register_user(constants.url, email, username, password)
    print("\nResponse:\n {}".format(response))

    if ("Please enter" not in response):
        create_contacts_list(username) #create the contacts list table
        print("Redirecting you to the login menu...")
        login() #go to login menu

def get_username_list():
    usernames = json.loads(get_all_users(constants.url))
    username_list = usernames['all usernames']
    return username_list

"""Menu 2"""
def chatroom_menu():
    cont = True
    while(cont):
        print("\nDisplaying menu options. To select an option enter the integer without punctuation.")
        print("Select an option:")
        print("1. Send a message")
        print("2. Get messages")
        print("3. Add new contact")
        print("3. Quit")

        choice = input()
        if (choice == "1"):
            send_msg()
        elif (choice == "2"):
            get_msg()
        elif (choice == "3"):
            print("Exiting program. Goodbye.\n")
            cont = False
        else:
            print("Invalid input. Please enter 1, 2, or 3.\n")

def rsa_keypair_gen():
    #return public and private key pair
    pass

def send_msg():
    print("You entered '1': Send a message\n")
    #while input is not -1
    username_list = get_username_list()
    print("\nPlease select the username of the user you would like to communicate with from the following list.")
    print(username_list)
    choice = input()
    if choice in username_list:
        print("{} is in {}".format(choice, username_list))
        if choice in session_user.contacted_users:
            #get private key
            if (len(session_user.private_keys)) is not 0:
                private_key_path = session_user.private_keys[username]
            another = True
            if(another):
                pass
                #prompt user for message
                #check message length
                #encrypt message
                #post message
                #ask if they want to send another
                    #no ==> another = False
        else:
            print("You have not communicated with that user before. Please send them the following keys so you can communicate with them.")
            their_key_pair = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            my_key_pair = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            #generate keys and ask the user to send it to the other party using email
    else:
        print("That is not a valid registered username. Try again..")

def get_msg():
    print("You entered '2': Get messages\n")
    #get messages and display them


"""
    Driver
"""
session_user = Registered_User(username=0,access_tok=0,refresh_tok=0)
username_list = get_username_list()

login_register()
