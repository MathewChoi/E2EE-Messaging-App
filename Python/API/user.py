import sqlite3
import json
import secrets
import hashlib

from flask_restful import Resource, reqparse
from flask_jwt_extended import jwt_required

"""
    This resource describes all the users in the application. All users have an email, username, password, and salt. The password is salted with the salt and hashed with SHA512 before it is stored.
"""
class User(Resource):
    TABLE_NAME = 'users'
    DATABASE_NAME = 'data.db'

    def __init__(self, **kwargs):
        self.email = kwargs["email"]
        self.username = kwargs["username"]
        self.password = kwargs["password"]
        self.salt = kwargs["salt"]

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)

    def serialize(self):
        return self.__dict__

    def printUser(self):
        print("email={}\nusername={}\npassword={}\nsalt={}".format(self.email, self.username, self.password,self.salt))

    @classmethod
    def find_by_username(cls, username):
        #connect to the database
        connection = sqlite3.connect(cls.DATABASE_NAME)
        cursor = connection.cursor()

        #obtain the first user with the username
        query = "SELECT * FROM {table} WHERE username=?".format(table=cls.TABLE_NAME)
        result = cursor.execute(query, (username,))
        match = result.fetchone()
        if match:
            #convert the result into a user object
            email = match[0]
            username = match[1]
            password =match[2]
            salt = match[3]

            user = User(email=email, username=username, password=password, salt=salt)
            user.printUser()
        else:
            user = None
        #close the connection to the database
        connection.close()
        return user

    @classmethod
    def find_by_email(cls, email):
        #connect to the database
        connection = sqlite3.connect(cls.DATABASE_NAME)
        cursor = connection.cursor()

        #obtain the first user with the email
        query = "SELECT * FROM {table} WHERE email=?".format(table=cls.TABLE_NAME)
        result = cursor.execute(query, (email,))
        match = result.fetchone()
        if match:
            #convert the result into a user object
            email = match[0]
            username = match[1]
            password =match[2]
            salt = match[3]

            user = User(email=email, username=username, password=password, salt=salt)
            user.printUser()
        else:
            user = None

        #close the connection to the database
        connection.close()
        return user

class UserRegister(Resource):
    TABLE_NAME = 'users'
    DATABASE_NAME = 'data.db'

    parser = reqparse.RequestParser()
    parser.add_argument("email",
        type=str,
        required=False
    )
    parser.add_argument('username',
        type=str,
        required=True,
        help="This field cannot be left blank!"
    )
    parser.add_argument('password',
        type=str,
        required=True,
        help="This field cannot be left blank!"
    )

    """
        Registers a new user into the system
    """
    def post(self):
        data = UserRegister.parser.parse_args()

        #store data in variables
        email = data["email"]
        username = data['username']
        password = data['password']

        if User.find_by_username(username): #check if a user with the same username already exits
            return {"message": "User with that username already exists. Please enter a new username."}, 401

        if User.find_by_email(email): #check if a user with the same email already exists
            return {"message": "That email is already in use. Please enter a new email address."}, 401

        #connect to the database
        connection = sqlite3.connect(self.DATABASE_NAME)
        cursor = connection.cursor()

        #hash and salt the password
        salt = secrets.token_hex(16)
        salted_pass = password + str(salt)
        sha512 = hashlib.sha512(salted_pass.encode('UTF-8'))
        digest = sha512.digest()

        #add the user to the users table
        query = "INSERT INTO {table} VALUES (?, ?, ?, ?)".format(table=self.TABLE_NAME)
        cursor.execute(query, (email, username, str(digest), salt))
        print("username = {}".format(username))
        print("digest = {}".format(digest))
        print("salt = {}".format(salt))

        #save changes to the database and close connection
        connection.commit()
        connection.close()

        return {"message": "User created successfully.", "username": data['username']}, 200


'''
    Used to request the list of all users, so we can see the changes each time
    a new user is added to the UserRegister.

    CLASS IS FOR TESTING PURPOSES ONLY
'''
class UserList(Resource):
    DATABASE_NAME = 'data.db'
    """
        This will return the list of users so we can confirm that the tables have been changed
    """
    def get(self):
        #connect to the database
        connection = sqlite3.connect(self.DATABASE_NAME)
        cursor = connection.cursor()

        #return the list of users
        query = "SELECT * FROM {}".format("users") #TABLE_NAME
        result = cursor.execute(query)

        #store all users in a list
        all_usernames = []
        for row in result:
            all_usernames.append(row[1])

        #close connection to database
        connection.close()

        #return all user data
        return {"all usernames":all_usernames}, 200
