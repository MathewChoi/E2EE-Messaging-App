import requests
import json

"""
    This file contains the requests methods that will be called in the application to the RESTful API
        references: https://realpython.com/blog/python/api-integration-in-python/
"""

#declare constants... DO NOT CHANGE THE CONTENTS OF THESE VARIABLES
class constants:
    url = 'http://127.0.0.1:5000'

def register_user(url, username, password):
    #setup the request route
    route = '/register'
    request_url = constants.url + route
    print("request_url = {}".format(request_url))

    data = {
        'username' : username,
        'password' : password
    }
    response = requests.post(request_url, data=data)

    if response.text:
        return response.text
    else:
        print("Oops, something went wrong. Sorry about that.")

def auth_user(url, username, password):
    #setup the request route
    route = '/auth'
    request_url = constants.url + route
    print("request_url = {}".format(request_url))

    data = {
        "username" : username,
        "password" : password
    }

    response = requests.post(request_url, data=data)

    if response.text:
        print(response.text, response)
        return response.text
    else:
        print("Oops, something went wrong. Sorry about that.")

def refresh_token(url, refresh_tok):
    #setup the request route
    route = '/auth'
    request_url = constants.url + route
    print("request_url = {}".format(request_url))

    headers = {
        "Authorization" : "Bearer "+refresh_tok
    }
    response = requests.put(request_url, headers=headers)

    if response.text:
        print(response.text, response)
        return response.text
    else:
        print("Oops, something went wrong. Sorry about that.")

def send_message(url, sender, receiver, ciphertext, access_tok):
    #setup the request route
    route = '/message'
    request_url = constants.url + route
    print("request_url = {}".format(request_url))

    headers = {
        "Authorization" : "Bearer "+access_tok,
        "Content-Type" : "application/json"
    }
    data = {
        "sender" : sender,
        "receiver" : receiver,
        "ciphertext" : ciphertext
    }
    print("data = {}".format(data))
    response = requests.post(request_url, headers=headers, data=json.dumps(data))

    if response.text:
        print(response.text, response)
        return response.text
    else:
        print("Oops, something went wrong. Sorry about that.")

def get_messages(url, receiver, access_tok):
    #setup the request route
    route = '/message/'
    request_url = constants.url + route + str(receiver)
    print("request_url = {}".format(request_url))

    headers = {
        "Authorization" : "Bearer "+access_tok
    }

    response = requests.get(request_url, headers=headers)

    if response.text:
        print(response.text, response)
        return response.text
    else:
        print("Oops, something went wrong. Sorry about that.")


"""
    The following functions exist for testing purposes, and should be removed from the application before launch
"""
def print_all_users(url):
    route = '/users'
    request_url = constants.url + route

    response = requests.get(request_url)

    if response.text:
        print(response.text, response)
    else:
        print("An error has occurred. Sorry bout that.")

"""
    Driver
"""
sender = username = "mathew"
password = "choi"
receiver = "ryan"
receiver_pass = "riehl"
ciphertext = "hey chump"

# testing print_all_users
#print('printing all users')
#print_all_users(constants.url)

#testing register_user
#register_user(constants.url, "ryan", "riehl")

#testing auth_user
print("testing user authentication")
tokens = json.loads(auth_user(constants.url, username, password))

access_tok = tokens['access token']
refresh_tok = tokens['refresh token']
print('access token = {}\n'.format(access_tok))
print('refresh token = {}'.format(refresh_tok))

#testing refresh_token
new_token  = json.loads(refresh_token(constants.url, refresh_tok)) #generates a new 'fresh' access_token
access_tok = new_token["access token"]
print('[NEW] access token = {}\n'.format(access_tok))

#testing post message
#print("Trying to post a message")
#post_msg = send_message(constants.url, sender, receiver, ciphertext, access_tok)

print("getting receiver tokens")
receiver_tokens = json.loads(auth_user(constants.url, receiver, receiver_pass))

#testing get message
get_msg = get_messages(constants.url, receiver, receiver_tokens['access token'])
