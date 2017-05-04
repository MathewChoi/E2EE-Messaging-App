from flask_restful import Resource, reqparse
from flask_jwt_extended import jwt_required, get_jwt_identity
from user import UserRegister
from datetime import datetime

import sqlite3
import json

"""
    This class describes the messages sent from user to user. Each message has a sender, receiver, ciphertext, timestamp, and read bit.
"""
class Message(Resource):
    TABLE_NAME = 'messages'

    def __init__(self, sender, ciphertext, receiver):
        self.sender = "sender"
        self.ciphertext = "ciphertext"
        self.receiver = "receiver"

    """
        Needed to avoid missing positional arguments error
    """
    def __init__(self):
        pass

    """
        If any new arguments are added to the request,
        add them to the list below
    """
    parser = reqparse.RequestParser()
    parser.add_argument("sender",
        type=str,
        required=True,
        help="This field cannot be left blank!"
    )
    parser.add_argument("receiver",
        type=str,
        required=True,
        help="This field cannot be left blank!"
    )
    parser.add_argument("ciphertext",
        type=str,
        required=True,
        help="This field cannot be left blank!"
    )


    @classmethod
    def find_by_receiver(cls, receiver):
        #connects to a database
        connection = sqlite3.connect('data.db')
        cursor = connection.cursor()

        #finds a user with the username = receiver
        query = "SELECT * FROM {table} WHERE receiver=?".format(table=cls.TABLE_NAME)
        result = cursor.execute(query, (receiver,))

        messages = {}
        message_num = 0
        for row in result:
            #converts each row in the result set into a message object
            message = {
                "sender": row[0],
                "receiver": row[1],
                "ciphertext": row[2],
                "time_stamp": row[3],
                "read": row[4]
            }
            messages.update({"message{}".format(message_num):message})
            message_num += 1

        #close the connection to the database
        connection.close()
        return messages

    """
        Marks the messages the get request returns as read
    """
    @classmethod
    def mark_read(cls, read_messages):
        #connect to the database
        connection = sqlite3.connect('data.db')
        cursor = connection.cursor()

        #iterate through messages and mark each as read
        for k,v in read_messages.items():
            query = "UPDATE {table} SET read=1 WHERE sender=? AND receiver=? AND time_stamp=?".format(table=cls.TABLE_NAME)
            cursor.execute(query,(v["sender"], v["receiver"], v['time_stamp']))

        #close the connection to the database
        connection.commit()
        connection.close()

    """
        Deletes messages where the read bit is raised
    """
    @classmethod
    def delete_read(cls):
        #connect to the database
        connection = sqlite3.connect('data.db')
        cursor = connection.cursor()

        #delete messages from messages table with the read bit raised
        query = "DELETE FROM {table} WHERE read=1".format(table=cls.TABLE_NAME)
        cursor.execute(query)

        #close the connection to the database
        connection.commit()
        connection.close()

    '''
        inserts a new message into the messages table
    '''
    @jwt_required
    def post(self):
        data = Message.parser.parse_args()

        print("data = {}".format(type(data)))

        sender = data["sender"]
        current_user = json.loads(get_jwt_identity()) # need to remove json loads for when not testing with Postman
        username = current_user["username"]

        if (sender == username): # verify that the user is sending the message under their name
            time_stamp = datetime.now()

            #connects to the database
            connection = sqlite3.connect("data.db")
            cursor = connection.cursor()

            #adds the message to the messages table
            query = "INSERT INTO {} (sender, receiver, ciphertext, time_stamp, read) VALUES (?,?,?,?,?)".format(self.TABLE_NAME)
            cursor.execute(query, (data["sender"], data["receiver"], data["ciphertext"], time_stamp, 0))

            #closes the connection to the database
            connection.commit()
            connection.close()

            return {"message": "message post successfully completed"}, 201
        else:
            return {"message": "you cannot send a message under a different username."}, 204


class MessageList(Resource):
    def __init__(self):
        pass

    """
        Gets the unread messages for a user
    """
    @jwt_required
    def get(self, receiver):
        messages = Message.find_by_receiver(receiver)
        if messages: # ie message exists
            Message.mark_read(messages)
            Message.delete_read()
            return {"messages": messages}
        return {'message':'No new messages for this receiver'}, 204 #204 = no content for user
