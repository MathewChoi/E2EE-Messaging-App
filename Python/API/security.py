from werkzeug.security import safe_str_cmp
from user import User

'''
    returns the payload for JWT
'''
def authenticate(username, password):
    user = User.find_by_username(username)
    if user and safe_str_cmp(user.password, password):
        return user

'''
    creates the signature for JWT
'''
def identity(payload):
    user_id = payload['identity']
    print("user_id = {}".format(user_id))
    return User.find_by_id(user_id)
