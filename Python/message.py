from flask_restful import Resource, reqparse
from flask_jwt import jwt_required
from user import UserRegister
from datetime import datetime
import sqlite3

class Message(Resource):
    TABLE_NAME = 'messages'

    parser = reqparse.RequestParser()
    parser.add_argument('sender',
        type=str,
        required=True,
        help="This field cannot be left blank!"
    )
    parser.add_argument('receiver',
        type=str,
        required=True,
        help="This field cannot be left blank!"
    )
    parser.add_argument('ciphertext',
        type=str,
        required=True,
        help="This field cannot be left blank!"
    )

    @jwt_required
    def get(self, receiver):
        messages = self.find_by_receiver(receiver)
        if messages: # ie message exists
            return messages
        return {'message':'No new messages for this receiver'}, 404

    @classmethod
    def find_by_receiver(receiver):
        connection = sqlite3.connect('data.db')
        cursor = connection.cursor()

        query = "SELECT * FROM {table} WHERE receiver=?".format(table=cls.TABLE_NAME)
        result = cursor.execute(query, (receiver,))

        connection.close()

        messages = {}
        message_num = 0
        for row in result:
            messages.update({"message{}".format(message_num):row})
            message_num += 1
        return messages

    # inserts a message into messages table
    @jwt_required
    def post(self, receiver, ciphertext):
        jwt = flask_restful.current_identity()
        user_dict = UserRegister.find_by_jwt()
        sender = user_dict["username"]

        if sender != "Invalid token: token does not match any user.":
            connection = sqlite3.connect('data.db')
            cursor = connection.cursor()

            query = "INSERT INTO {table} (sender, receiver, ciphertext, time_stamp, read) VALUES (?,?,?,?,?)"
            time_stamp = datetime.now()
            cursor.execute(query, (sender, receiver, ciphertext, time_stamp, 0))

            connection.commit()
            connection.close()

            return {"message" : "Message successfully added to database."}
        else:
            return {"message" : "Error: message was not added to database."} # probably need to check jwt

    @jwt_required
    def put(self, sender, receiver, time_stamp):
        jwt = flask_restful.current_identity()
        user_dict = UserRegister.find_by_jwt()
        receiver = user_dict["username"]

        if receiver != "Invalid token: token does not match any user.":
            connection = sqlite3.connect('data.db')
            cursor = connection.cursor()

            query = "UPDATE {table} SET read=1 WHERE sender=? and receiver=? and time_stamp=?"
            result = cursor.execute(query, (sender, receiver, time_stamp))

            connection.commit()
            connection.close()
            if result:
                return {"message" : "Message successfully added to database."}

        # no row is updated OR jwt is invalid
        return {"message" : "Error: message was not added to database."} # probably need to check jwt
