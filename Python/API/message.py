from flask_restful import Resource, reqparse
from flask_jwt_extended import jwt_required, get_jwt_identity
from user import UserRegister
from datetime import datetime
import sqlite3
import json

class Message(Resource):
    TABLE_NAME = 'messages'

    def __init__(self, sender, ciphertext, receiver, read):
        self.sender = "sender"
        self.ciphertext = "ciphertext"
        self.receiver = "receiver"
        self.read = False

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
    parser.add_argument("read",
        type=bool,
        required=True,
        help="This field cannot be left blank!"
    )

    @classmethod
    def find_by_receiver(cls, receiver):
        connection = sqlite3.connect('data.db')
        cursor = connection.cursor()

        query = "SELECT * FROM {table} WHERE receiver=?".format(table=cls.TABLE_NAME)
        result = cursor.execute(query, (receiver,))

        messages = {}
        message_num = 0
        for row in result:
            message = {
                "sender": row[0],
                "receiver": row[1],
                "ciphertext": row[2],
                "time_stamp": row[3],
                "read": row[4]
            }
            messages.update({"message{}".format(message_num):message})
            message_num += 1

        connection.close()
        return messages

    @classmethod
    def mark_read(cls, messages):
        connection = sqlite3.connect('data.db')
        cursor = connection.cursor()

        #iterate through messages and mark each as read
        for k,v in messages.items():
            query = "UPDATE {table} SET read=1 WHERE sender=? AND receiver=? AND time_stamp=?".format(table=cls.TABLE_NAME)
            cursor.execute(query,(v['sender'], v['receiver'], v['time_stamp']))

        connection.commit()
        connection.close()


    '''
        inserts a new message into the messages table
    '''
    @jwt_required
    def post(self):
        data = Message.parser.parse_args()

        sender = data["sender"]

        current_user = json.loads(get_jwt_identity()) #convert jwt identity (user obj as a str) to a json
        username = current_user["username"]

        if (sender == username): # verify that the user is sending the message under their name
            time_stamp = datetime.now()

            connection = sqlite3.connect("data.db")
            cursor = connection.cursor()

            query = "INSERT INTO {} (sender, receiver, ciphertext, time_stamp, read) VALUES (?,?,?,?,?)".format(self.TABLE_NAME)
            cursor.execute(query, (data["sender"], data["receiver"], data["ciphertext"], time_stamp, data["read"]))

            connection.commit()
            connection.close()

            return {"message": "message post successfully completed"}

        else:
            return {"message": "you cannot send a message under a different username"}

    @jwt_required
    def put(self, sender, receiver, time_stamp):
        #jwt = flask_restful.current_identity()
        #user_dict = UserRegister.find_by_jwt()
        #receiver = user_dict["username"]

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

class MessageList(Resource):
    def __init__(self):
        pass

    @jwt_required
    def get(self, receiver):
        messages = Message.find_by_receiver(receiver)
        if messages: # ie message exists
            #mark all messages as read
            Message.mark_read(messages)
            return {"messages": messages}
        return {'message':'No new messages for this receiver'}, 404
