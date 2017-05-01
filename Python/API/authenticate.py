"""
    This class handles requests to create a new account, authenticate a user (for login), and refresh a token. When a user is authenticated, they are given an access token (JWT) and a refresh token. The access token has a shorter "freshness" period and will need to be replaced frequently, which can be done by passing the refresh token to the put request. On the other hand, the refresh token has a longer "freshness" period, so it will need to be stored securely. If it is ever stolen, an adversary may be able to impersonate a different user. 
"""
import sqlite3
import json

from werkzeug.security import safe_str_cmp
from flask import jsonify
from flask_jwt_extended import set_access_cookies, set_refresh_cookies, create_access_token, create_refresh_token, jwt_refresh_token_required, get_jwt_identity
from flask_restful import Resource, reqparse

from user import User

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

    """
        authenticates the user by comparing their username and password
    """
    def post(self):
        data = Authenticator.parser.parse_args()

        #get username and password
        username = data["username"]
        password = data["password"]

        user = User.find_by_username(username)
        if (user and safe_str_cmp(user.password, password)) is False:
            return {"Message" : "invalid username or password"}, 401

        #set the JWT cookies in the responses
        resp = {
            "access token": create_access_token(identity=user.toJSON()),
            "refresh token": create_refresh_token(identity=user.toJSON())
            }
        return jsonify(resp)


    """
        generates a new access token for the user based off of their refresh token
    """
    @jwt_refresh_token_required
    def put(self):
        current_user = json.loads(get_jwt_identity())

        ret = {
            "access token": create_access_token(identity=current_user)
        }
        return jsonify(ret)
