import json

from flask import Flask, request
from flask_restful import Api
from flask_jwt_extended import JWTManager

from authenticate import Authenticator
from user import UserRegister, UserList
from message import Message, MessageList

app = Flask(__name__)

"""
    Configuration of application
"""
app.config['JWT_TOKEN_LOCATION'] = ['headers', 'cookies']


api = Api(app)

'''
    Documentation for flask_jwt_extended: https://flask-jwt-extended.readthedocs.io/en/latest/
'''
#jwt = JWT(app, authenticate, identity) # generates a new jwt with each auth call
jwt = JWTManager(app)

api.add_resource(Message, '/message')
api.add_resource(MessageList, '/message/<string:receiver>')
api.add_resource(Authenticator, '/auth')
api.add_resource(UserRegister, '/register')
api.add_resource(UserList, '/users')

if __name__ == '__main__':
    app.run(debug=True)  # important to mention debug=True
