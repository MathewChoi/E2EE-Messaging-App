
import sqlite3
import flask_restful
from flask_restful import Resource, reqparse
from flask_jwt import jwt_required


class User(Resource):
    TABLE_NAME = 'users'

    def __init__(self, _id, username, password, jwt):
        self.id = 0
        self.username = 0
        self.password = 0
        self.jwt = 0

    @classmethod
    def find_by_username(cls, username):
        connection = sqlite3.connect('data.db')
        cursor = connection.cursor()

        query = "SELECT * FROM {table} WHERE username=?".format(table=cls.TABLE_NAME)
        result = cursor.execute(query, (username,))
        row = result.fetchone()
        if row:
            user = cls(*row)
            #user = User(row["_id"], row["username"], row["password"], row["jwt"])
        else:
            user = None

        connection.close()
        return user

    @classmethod
    def find_email_by_username(cls, username):
        ''' I don't know if this works '''
        connection = sqlite3.connect('data.db')
        cursor = connection.cursor()

        query = "SELECT email FROM {table} WHERE username=?".format(table=cls.TABLE_NAME)
        result = cursor.execute(query, (username,))
        row = result.fetchone()
        if not row:
            row = None

        connection.close()
        return row

    @classmethod
    def find_by_id(cls, id):
        connection = sqlite3.connect('data.db')
        cursor = connection.cursor()

        query = "SELECT * FROM {table} WHERE id=?".format(table=cls.TABLE_NAME)
        result = cursor.execute(query, (id,))
        row = result.fetchone()
        if row:
            user = cls(*row)
            #user = User(row["_id"], row["username"], row["password"], row["jwt"])
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

    # adds a new user
    def post(self):
        data = UserRegister.parser.parse_args()

        if User.find_by_username(data['username']):
            return {"message": "User with that username already exists."}, 400

        #else connect to the database and add a new user to the users table
        connection = sqlite3.connect('data.db')
        cursor = connection.cursor()

        query = "INSERT INTO {table} VALUES (NULL, ?, ?, ?)".format(table=self.TABLE_NAME)
        cursor.execute(query, (data['username'], data['password'], "0")) # need to salt-and-hash the password

        connection.commit()
        connection.close()

        return {"message": "User created successfully.", "username": data['username'], "password": data['password']}, 201

    # finds user by jwt
    @classmethod
    def find_by_jwt(cls, jwt):
        connection = sqlite3.connect('data.db')
        cursor = connection.cursor()

        query = "SELECT username FROM {table} WHERE jwt=?".format(table=self.TABLE_NAME)
        result = cursor.execute(query, (jwt,))

        if result is not None:
            return {"username" : result["username"]}
        else:
            return {"username" : "Invalid token: token does not match any user."}

    # first time jwt update
    @jwt_required
    def put(self, user):
        connection = sqlite3.connect('data.db')
        cursor = connection.cursor()

        query = "SELECT jwt FROM {table} WHERE username=?".format(table=self.TABLE_NAME)
        result = cursor.execute(query, (user,))
        one_result = cursor.fetchone()
        if one_result['jwt'] == "0":
            query = "UPDATE {table} set jwt=? where username=?".format(table=self.TABLE_NAME)
            jwt = flask_restful.current_identity()
            result = cursor.execute(query,(jwt, user))

            connection.commit()
            connection.close()

            if result:
                return {"message" : "jwt successfully updated."}
            else:
                return {"message" : "jwt was not updated."}
        else:
            return {"message" : "updating jwt is unauthorized."}


class UserList(Resource):

    # this request will display all users so we can see the changes each request makes
    # FOR TESTING PURPOSES ONLY
    def get(self):
        connection = sqlite3.connect('data.db')
        cursor = connection.cursor()

        query = "SELECT * FROM {}".format("users") #TABLE_NAME
        result = cursor.execute(query)

        all_users = {}
        user_num = 1
        for row in result:
            key = "user_" + str(user_num)
            all_users[key] = {
            "id" : row[0],
            "username" : row[1],
            "password" : row[2],
            "jwt" : row[3]
            }
            user_num = user_num + 1

        connection.close()

        return {"all_users":all_users, "num_users": user_num}
