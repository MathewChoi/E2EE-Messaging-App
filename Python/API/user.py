import sqlite3
import json
import secrets
import hashlib

from flask_restful import Resource, reqparse
from flask_jwt_extended import jwt_required

class User(Resource):
    TABLE_NAME = 'users'

    def __init__(self, **kwargs):
        self._id = kwargs["_id"]
        self.username = kwargs["username"]
        self.password = kwargs["password"]
        self.salt = kwargs["salt"]

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)

    def serialize(self):
        return self.__dict__

    def printUser(self):
        print("id={}\nusername={}\npassword={}\nsalt={}".format(self._id, self.username, self.password,self.salt))

    @classmethod
    def find_by_username(cls, username):
        connection = sqlite3.connect('data.db')
        cursor = connection.cursor()

        query = "SELECT * FROM {table} WHERE username=?".format(table=cls.TABLE_NAME)
        result = cursor.execute(query, (username,))
        match = result.fetchone()
        if match:
            #user = cls(*row)
            _id = match[0]
            username = match[1]
            password =match[2]
            salt = match[3]

            user = User(_id=_id, username=username, password=password, salt=salt)
            user.printUser()
        else:
            user = None

        connection.close()
        return user

    @classmethod
    def find_by_id(cls, _id):
        connection = sqlite3.connect('data.db')
        cursor = connection.cursor()

        query = "SELECT * FROM {table} WHERE _id=?".format(table=cls.TABLE_NAME)
        result = cursor.execute(query, (_id,))
        row = result.fetchone()
        if row:
            #user = cls(*row)
            _id = row[0]
            username = row[1]
            password = row[2]

            user = User(_id=_id, username=username, password=password)
            user.printUser()
        else:
            user = None

        connection.close()
        return user

class UserRegister(Resource):
    TABLE_NAME = 'users'

    parser = reqparse.RequestParser()
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
        data = UserRegister.parser.parse_args() # TODO make sure the password is encrypted before sending

        username = data['username']
        password = data['password']

        if User.find_by_username(username): #check if a user with the same username already exits
            return {"message": "User with that username already exists."}, 400

        #else connect to the database
        connection = sqlite3.connect('data.db')
        cursor = connection.cursor()

        #hash and salt the password
        salt = secrets.token_hex(16)
        salted_pass = password + str(salt)
        sha512 = hashlib.sha512(salted_pass.encode('UTF-8'))
        digest = sha512.digest()

        #add the user to the users table
        query = "INSERT INTO {table} VALUES (NULL, ?, ?, ?)".format(table=self.TABLE_NAME)
        cursor.execute(query, (username, str(digest), salt))
        print("username = {}".format(username))
        print("digest = {}".format(digest))
        print("salt = {}".format(salt))

        #save changes to the database and close connection
        connection.commit()
        connection.close()

        return {"message": "User created successfully.", "username": data['username'], "password": data['password']}, 201


'''
    Used to request the list of all users, so we can see the changes each time
    a new user is added to the UserRegister.

    CLASS IS FOR TESTING PURPOSES ONLY
'''
class UserList(Resource):
    def get(self):
        connection = sqlite3.connect('data.db')
        cursor = connection.cursor()

        query = "SELECT * FROM {}".format("users") #TABLE_NAME
        result = cursor.execute(query)

        all_users = {}
        user_num = 0
        for row in result:
            key = "user_" + str(user_num)
            all_users[key] = {
                "id" : row[0],
                "username" : row[1],
                "password" : row[2],
                "salt":row[3]
            }
            user_num = user_num + 1

        connection.close()

        return {"num_users": user_num, "all_users":all_users}
