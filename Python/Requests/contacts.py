import sqlite3

def create_contacts_list(username):
    DATABASE_NAME = username+'_contacts.db'
    print("database name = {}".format(DATABASE_NAME))

    connection = sqlite3.connect(DATABASE_NAME)
    cursor = connection.cursor()

    create_table = "CREATE TABLE IF NOT EXISTS contacts (contact text, public_key text, private_key text)"
    cursor.execute(create_table)

    connection.commit()
    connection.close()

def get_contacted_users(username):
    DATABASE_NAME = username+'_contacts.db'
    print("database name = {}".format(DATABASE_NAME))

    connection = sqlite3.connect(DATABASE_NAME)
    cursor = connection.cursor()

    create_contacts_list(username)

    get_contacted = "SELECT contact from contacts"
    result = cursor.execute(get_contacted)

    contact_list = []
    for person in result:
        contact = person[0]
        contact_list.append(contact)

    connection.commit()
    connection.close()

    return contact_list

def get_public_keys(username):
    DATABASE_NAME = username+'_contacts.db'
    print("database name = {}".format(DATABASE_NAME))

    connection = sqlite3.connect(DATABASE_NAME)
    cursor = connection.cursor()

    get_pub_keys = "SELECT contact, public_key from contacts"
    result = cursor.execute(get_pub_keys)

    pub_keys = {}
    for pair in result:
        contact = pair[0]
        pub_key = pair[1]
        pub_keys[contact] = pub_key

    connection.commit()
    connection.close()

    return pub_keys

def get_private_keys(username):
    DATABASE_NAME = username+'_contacts.db'
    print("database name = {}".format(DATABASE_NAME))

    connection = sqlite3.connect(DATABASE_NAME)
    cursor = connection.cursor()

    get_priv_keys = "SELECT contact, private_key from contacts"
    result = cursor.execute(get_priv_keys)

    priv_keys = {}
    for pair in result:
        contact = pair[0]
        priv_key = pair[1]
        priv_keys[contact] = priv_key

    connection.commit()
    connection.close()

    return priv_keys

def add_contact(username, contact):
    DATABASE_NAME = username+'_contacts.db'
    print("database name = {}".format(DATABASE_NAME))

    connection = sqlite3.connect(DATABASE_NAME)
    cursor = connection.cursor()

    add_contact_info = "INSERT INTO contacts (contact) VALUES (?)"
    cursor.execute(add_contact_info, (contact,))

    connection.commit()
    connection.close()

def change_priv_keys(username, contact, new_priv_keys):
    DATABASE_NAME = username+'_contacts.db'
    print("database name = {}".format(DATABASE_NAME))

    connection = sqlite3.connect(DATABASE_NAME)
    cursor = connection.cursor()

    add_contact_info = "UPDATE contacts set private_key = ? WHERE contact = ?"
    cursor.execute(add_contact_info, (new_priv_keys, contact))

    connection.commit()
    connection.close()

def change_pub_keys(username, contact, new_pub_keys):
    DATABASE_NAME = username+'_contacts.db'
    print("database name = {}".format(DATABASE_NAME))

    connection = sqlite3.connect(DATABASE_NAME)
    cursor = connection.cursor()

    add_contact_info = "UPDATE contacts set public_key = ? WHERE contact = ?"
    cursor.execute(add_contact_info, (new_pub_keys, contact))

    connection.commit()
    connection.close()
"""
    Driver

username = 'mathew'
contact = 'ryan'
pub_key = contact+'pub'
priv_key = contact+'priv'

create_contacts_list(username)

print('\nbefore adding contact')
contact_list = get_contacted_users(username)
print("previously contacted people = {}".format(contact_list))

add_contact(username, contact, pub_key, priv_key)

print('\nafter adding contact')
contact_list = get_contacted_users(username)
print("previously contacted people = {}".format(contact_list))

print('\ngetting public keys')
pub_keys = get_public_keys(username)
print("contacts' public key map = {}".format(pub_keys))

print('\ngetting private keys')
priv_keys = get_private_keys(username)
print("contacts' private key map = {}".format(priv_keys))
"""
