import sqlite3
import json
import hashlib

from werkzeug.security import safe_str_cmp
from flask import jsonify
from flask_jwt_extended import set_access_cookies, set_refresh_cookies, create_access_token, create_refresh_token, jwt_refresh_token_required, get_jwt_identity
from flask_restful import Resource, reqparse

from user import User

"""
    This class is used to: verify whether a user has the correct credentials to access an account, and refresh access tokens.
"""
class Authenticator(Resource):
    def __init__(self):
        pass

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

    @classmethod
    def compare_passwords(cls, user, attempt):
        #get salt
        salt = user.salt
        #hash attempt||salt
        salted_attempt = attempt + salt
        #compare digest with stored digest
        sha512 = hashlib.sha512(salted_attempt.encode('UTF-8'))
        digest = sha512.digest()
        pass_match = safe_str_cmp(user.password, str(digest))
        return pass_match

    """
        Authenticates the user by comparing their username and password
    """
    def post(self):
        data = Authenticator.parser.parse_args()

        #get username and password
        username = data["username"]
        password = data["password"]

        user = User.find_by_username(username)
        if user is None:
            return {"Message" : "A user with that username does not exist in the system."}
        pass_match = Authenticator.compare_passwords(user, password)

        if pass_match is False:
            return {"Message" : "Invalid username or password"}, 401 #401 = unauthorized

        #set the JWT cookies in the responses
        resp = {
            "access token": create_access_token(identity=user.toJSON()),
            "refresh token": create_refresh_token(identity=user.toJSON())
            }
        return jsonify(resp)


    """
        Generates a new access token for the user based off of their refresh token
    """
    @jwt_refresh_token_required
    def put(self):
        current_user = json.loads(get_jwt_identity())
        ret = {
            "access token": create_access_token(identity=current_user)
        }
        return jsonify(ret)
