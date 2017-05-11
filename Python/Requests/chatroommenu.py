from make_requests import auth_user, register_user, refresh_token, send_message, get_messages, constants
import json
import rsa_encrypt_decrypt
import encrypt_decrypt
import contacts
import make_requests
from message import Message
from user import User, UserRegister

PATH_TO_PASS_DICT = "C:\\Users\Ryan\PycharmProjects\EncryptedChat\password_dict.txt"


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
    """Menu 1"""
    cont = True
    while(cont):
        print("\nDisplaying menu options. To select an option enter the integer without punctuation.")
        print("1. Login")
        print("2. Register")
        print("3. Exit")

        choice = input()
        if choice == "1":
            login()
        elif choice == "2":
            register()
        elif choice == "3":
            print("Exiting program. Goodbye.")
            cont = False
        else:
            print("Invalid input. Please enter 1, 2, or 3.")


def login():
    print("\nLogging in, enter your information.")
    print("Username: ")
    username = input()
    print("Password: ")
    password = input()
    response = auth_user(constants.url, username, password)
    # print("\nResponse:\n {}".format(response))
    if "access" in response:
        # get access and refresh tokens from server
        tokens = json.loads(response)
        session_user.username = username
        session_user.access_tok = tokens["access token"]
        session_user.refresh_tok = tokens["refresh token"]
        session_user.print()

        # read user info from database
        session_user.contacted_users = contacts.get_contacted_users(username)
        session_user.private_keys = contacts.get_private_keys(username)
        session_user.public_keys = contacts.get_public_keys(username)

        # show second menu
        chatroom_menu()
    else:
        print("Login failed.")


def register():
    print("\nEnter your information to register: ")
    print("Username: ")
    username = input()
    print("Email: ")
    email = input()
    password = get_valid_password()
    # TODO add the user to the DB


def get_valid_password():
    print("Password: ")
    password = input()
    while password in open(PATH_TO_PASS_DICT).read() or len(password) < 8:
        print("That password is too short or too common. Try again.\n")
        print("Password: ")
        password = input()
    print("Confirm password: ")
    password_check = input()
    while password != password_check:
        print("Passwords didn't match. Try again.\n")
        print("Password: ")
        password = input()
        while password in open(PATH_TO_PASS_DICT).read() or len(password) < 8:
            print("That password is too weak. Try again.\n")
            print("Password: ")
            password = input()
        print("Confirm password: ")
        password_check = input()
    return password


def chatroom_menu():
    """Menu 2"""
    cont = True
    while(cont):
        print("\nSelect an option:")
        print("1. Send a message")
        print("2. Check messages")
        print("3. List contacts")
        print("4. Add a contact")
        print("5. Save a user's public key")
        print("6. Quit")

        choice = input()
        if choice == "1":
            send_message()
        elif choice == "2":
            get_messages()
        elif choice == "3":
            list_contacts()
        elif choice == "4":
            add_contact()
        elif choice == "5":
            save_key()
        elif choice == "6":
            print("Exiting program. Goodbye.")
            cont = False
        else:
            print("Invalid input. Please enter an integer 1-6.")


def send_message():
    print("\nEnter the username of the person you want to message: ")
    username = input()
    if username in session_user.contacted_users:
        print("Enter your message: ")
        message = input()
        json_object = encrypt_decrypt.encrypt(message, session_user.public_keys[username])
        # TODO Not sure if I'm using the correct token here or the correct send message method
        make_requests.send_message(constants.url, session_user.username, username, json_object, session_user.access_tok)
        print("Message sent.")
    else:
        print("That username is not in your contacts. They must send you their public key before you can message them.")


def check_messages():
    # TODO Not sure if this will work
    print("\nYour new messages:")
    messages = Message.get(session_user.username)
    for num in messages:
        print(num, ": ")
        for msg in messages[num]:
            print(msg)


def list_contacts():
    print("\nYour current contacts are: ")
    for c in session_user.contacted_users:
        print(c)


def add_contact():
    print("\nEnter the username of the contact to add: ")
    username = input()

    user = User.find_by_username(username)
    if user is None:
        print("That username doesn't exist.")
        return
    else:
        # Getting the public/private key pair
        private_key = rsa_encrypt_decrypt.generate_private_key()

        # Storing your private key in your contacts DB so you can decrypt their messages
        contacts.add_contact(session_user.username, username, None, private_key)
        # Sending your public key to the contact so they can message you
        # TODO I'm not sure if this get email method will work
        rsa_encrypt_decrypt.send_public_key(private_key, User.find_email_by_username(username))
        print("Key sent. If they add you they'll be able to message you.")


def save_key():
    print("\nEnter the username of the contact: ")
    username = input()
    user = User.find_by_username(username)
    if user is None:
        print("That username doesn't exist.")
        return
    else:
        public_key = rsa_encrypt_decrypt.get_key_input()
        contacts.add_contact(session_user, username, public_key, None)


session_user = Registered_User(username=0, access_tok=0, refresh_tok=0)

login_register()
