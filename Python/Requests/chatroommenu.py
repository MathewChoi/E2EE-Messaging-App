#from make_requests import auth_user, register_user, refresh_token, send_message, get_messages, get_all_users, constants
from pathlib import Path
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
import json
import RSAEncryptDecrypt

PATH_TO_PASS_DICT = "C:\\Users\Ryan\PycharmProjects\EncryptedChat\password_dict.txt";


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
        if (choice == "1"):
            login()
        elif (choice == "2"):
            register()
        elif (choice == "3"):
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
    print("\nEnter your information to register: ")
    print("Username: ")
    username = input()
    print("Email: ")
    email = input()
    print("Password: ")
    password = get_valid_password()

    #storage file variables
    filepath = "//home//mathew//Desktop//CECS478//phase4//clientside//files//"
    contacted_filename = filepath+username+"_contacts.txt"
    public_keys_filename = filepath+username+"_publickeys.txt"
    private_keys_filename = filepath+username+"_privatekeys.txt"

    #create new files
    contacted_file = open(contacted_filename, "w")
    public_keys_file = open(public_keys_filename, "w")
    private_keys_file = open(private_keys_filename, "w")

    #close files
    contacted_file.close()
    public_keys_file.close()
    private_keys_file.close()


def get_valid_password():
    print("Password: ")
    password = input()
    while password in open(PATH_TO_PASS_DICT).read() or len(password) < 8:
        print("That password is too weak. Try again.\n")
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
        print("3. Add a contact")
        print("4. Quit")

        choice = input()
        if choice == "1":
            send_msg()
        elif choice == "2":
            get_msg()
        elif choice == "3":
            add_contact()
        elif choice == "4":
            print("Exiting program. Goodbye.")
            cont = False
        else:
            print("Invalid input. Please enter 1, 2, or 3.")


def get_contacted_users(username):
    #storage file variables
    filepath = "//home//mathew//Desktop//CECS478//phase4//clientside//files//"
    filename = filepath+username+"_contacts.txt"
    filepath = Path(filename)

    #open and read files
    if filepath.is_file():
        contacted_file = open(filename)
        for line in contacted_file:
            session_user.contacted_users.append(line)
        contacted_file.close()
    else:
        contacted_file = open(filename, "w")
        contacted_file.close()


def get_public_keys(username):
    #storage file variables
    filepath = "//home//mathew//Desktop//CECS478//phase4//clientside//files//"
    filename = filepath+username+"_publickeys.txt"
    filepath = Path(filename)

    #open and read files
    if filepath.is_file():
        public_keys_file = open(filename)
        content = ""
        for line in public_keys_file:
            content = content + line
            session_user.public_keys = json.loads(content)
        public_keys_file.close()
    else:
        public_keys_file = open(filename, "w")
        public_keys_file.close()


def get_private_keys(username):
    #storage file variables
    filepath = "//home//mathew//Desktop//CECS478//phase4//clientside//files//"
    filename = filepath+username+"_privatekeys.txt"
    filepath = Path(filename)

    #open files
    if filepath.is_file():
        private_keys_file = open(filename)
        content = ""
        for line in private_keys_file:
            content = content + line
            session_user.private_keys = json.loads(content)
        private_keys_file.close()
    else:
        private_keys_file = open(filename, "w")
        private_keys_file.close()


def get_username_list():
    usernames = json.loads(get_all_users(constants.url))
    username_list = usernames['all usernames']
    return username_list


def send_msg():
    print("Send a message: ")
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
        print("That is not a valid registered username. Try again..")


def get_msg():
    print("You entered '2': Get messages\n")
    # get messages and display them


def add_contact():
    print("\nEnter the username of the contact to add: ")
    username = input()
    # TODO need to check if contact is in the database
    if username not in database:
        print("That username doesn't exist.")
        return
    else:
        # TODO need to get the email for the entered username
        # email = username.get_email()
        private_key = RSAEncryptDecrypt.generate_private_key()
        # TODO Need to store this key in the DB
        public_key = RSAEncryptDecrypt.get_public_key(private_key)
        RSAEncryptDecrypt.send_public_key(private_key, email)

