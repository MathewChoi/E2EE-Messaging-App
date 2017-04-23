from flask import Flask, request
from flask_restful import Api
from flask_jwt import JWT

from security import authenticate, identity
from user import UserRegister, UserList
from message import Message

app = Flask(__name__)
app.secret_key = 'jose' # need a stronger secret_key
api = Api(app)

jwt = JWT(app, authenticate, identity) # generates a new jwt with each auth call

api.add_resource(Message, '/message/<string:sender>/<string:receiver>/<string:ciphertext>')
#api.add_resource(Message, '/message/<string:sender>/<string:receiver>/<string:time_stamp>')
api.add_resource(UserRegister, '/register')
api.add_resource(UserList, '/users')

if __name__ == '__main__':
    app.run(debug=True)  # important to mention debug=True
