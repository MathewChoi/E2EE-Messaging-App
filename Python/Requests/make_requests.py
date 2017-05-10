import requests
import json

"""
    This file contains the requests methods that will be called in the application to the RESTful API
        references: https://realpython.com/blog/python/api-integration-in-python/
"""

#declare constants... DO NOT CHANGE THE CONTENTS OF THESE VARIABLES
class constants:
    #local_url = 'http://127.0.0.1:5000'
    site_url = 'http://www.mathewchoi.me'

def register_user(url, email, username, password):
    #setup the request route
    route = '/register'
    request_url = constants.site_url + route

    data = {
        'email' : email,
        'username' : username,
        'password' : password
    }
    response = requests.post(request_url, data=data)

    return response.text

def auth_user(url, username, password):
    #setup the request route
    route = '/auth'
    request_url = constants.site_url + route

    data = {
        "username" : username,
        "password" : password
    }

    response = requests.post(request_url, data=data)

    return response.text

def refresh_token(url, refresh_tok):
    #setup the request route
    route = '/auth'
    request_url = constants.site_url + route

    headers = {
        "Authorization" : "Bearer "+refresh_tok
    }
    response = requests.put(request_url, headers=headers)

    return response.text

def send_message(url, sender, receiver, ciphertext, access_tok):
    #setup the request route
    route = '/message'
    request_url = constants.site_url + route

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

    return response.text

def get_messages(url, receiver, access_tok):
    #setup the request route
    route = '/message/'
    request_url = constants.site_url + route + str(receiver)

    headers = {
        "Authorization" : "Bearer "+access_tok
    }

    response = requests.get(request_url, headers=headers)

    return response.text


"""
    The following functions exist for testing purposes, and should be removed from the application before launch
"""
def get_all_users(url):
    route = '/users'
    request_url = constants.site_url + route

    response = requests.get(request_url)

    return response.text

"""
    Test Driver
"""
response_text = register_user(constants.site_url, "mathew.m.choi@gmail.com", "Mathew", "Choi")
print("response_text = {}".format(response_text))
