# Rhianna Smith and Leyla Jacoby
# COSC 55, Spring 2025, Lab 1

import json
import base64
from crypto_utils import encrypt, decrypt, generate_fernet_key
from auth import create_master_pw, validate_password

filename = "storage.json"

def menu(key):
    while True:
        print("\nWhat would you like to do today?")
        print("[1] Create a password")
        print("[2] Retrieve a password")
        print("[3] Update a password")
        print("[4] Delete a password")
        print("[5] Exit menu")
        choice = input("Enter a number: ")
        if choice == "1":
            print("[1] Create a password")
            create_pw(key)
        elif choice == "2":
            print("[2] Retreive a password")
            retreive_pw(key)
        elif choice == "3":
            print("[3] Update a password")
            update_pw(key)
        elif choice == "4":
            print("[4] Delete a password")
            delete_pw()
        elif choice == "5":
            print("Goodbye")
            break
        else:
            print("Invalid entry. Please try again")

def main():
    print("Welcome to the CLI Password Manager!")
    while True:
        print("Hello! Please type 'register' to register if you do not have a master password. Otherwise, type 'login' to login. Type 'exit' to end the program.")
        decision = input("Enter desire: ")
        if decision.lower() == "exit":
            break
        elif decision.lower() == "register":
            create_mpw()
        elif decision.lower() == "login":
            login_mpw()
            break

## function to run when user wants to create a master password
def create_mpw():
    data = read_json(filename)
    try:  ## check if there is a mpw
        if data['masterpassword_hash']:
            print("You have already set a master password.")

    except: ## if there isn't already a mpw
        # create & hash master password
        mpw = input("Please create a master password: ")
        salt, key = create_master_pw(mpw)

        ## put hashed mpw and the salt into the json
        data["masterpassword_hash"] = base64.urlsafe_b64encode(key).decode()
        data["salt"] = base64.urlsafe_b64encode(salt).decode()
        write_json(filename, data)

        # show password manager menu (logged in, with key)
        menu(key)

## function to run when user wants to log in using their master password
def login_mpw():
    pw_attempt = input("Please enter your master password: ")
    data = read_json(filename)

    ## load in salt & hashed master password from json
    salt = base64.urlsafe_b64decode(data["salt"].encode())
    mpw = base64.urlsafe_b64decode(data["masterpassword_hash"].encode())

    if validate_password(mpw, salt, pw_attempt.encode()):
        ## if entered password matches master password, generate Fernet key to encrypt & decrypt service passwords
        key = generate_fernet_key(pw_attempt, salt)

        # show password manager menu (logged in, with key)
        menu(key)
    else:
        print("That password doesn't match")

## Helper functions for CLI
def create_pw(key):
    ## collect service, username, and password for new entry
    service = input("What service is your password for? ").lower()
    username = input("Username: ").lower()
    pw = input("Password: ").lower()

    ## encrypt password
    encrypted_pw = encrypt(key, pw)

    # store info for new credentials in json
    data = read_json(filename)
    cred_dict = {'username': username, 'password': encrypted_pw}
    data[service] = cred_dict
    write_json(filename, data)

def retreive_pw(key):
    data = read_json(filename)
    service = input("What service is your password for? ")
    try: # if they have credentials for that service, decrypt password from json and print them
        if data[service]:
            username = data[service]['username']
            password = decrypt(key, data[service]['password'])
            print(f"For {service}, your username is {username} and your password is {password}")
    except:
        print("You don't have a password for that service.")

def update_pw(key):
    data = read_json(filename)
    service = input("What service do you want to update the password for? ")
    try: # if they have credentials for that service, encrypt new password and replace old password in json
        if data[service]:
            new_password = input("New password: ")
            encrypted_pw = encrypt(key, new_password)
            data[service]['password'] = encrypted_pw
            write_json(filename, data)
            print(f"Password updated for {service}")

    except:
        print("You don't have a password for that service.")

def delete_pw():
    data = read_json(filename)
    service = input("What service do you want to delete the password for? ")
    try: # if they have credentials for that service, delete the service & credentials from the json
        if data[service]:
            data.pop(service)
            print(f"Password deleted for {service}")
            write_json(filename, data)
    except:
        print("You don't have a password for that service.")

## Helper functions
def write_json(filename, data):
    with open(filename, 'w') as json_file:
        json.dump(data, json_file)

def read_json(filename):
    with open(filename, 'r') as json_file:
        return json.load(json_file)

def reset_init_for_testing():
    data = {}
    write_json(filename, data)

if __name__ == "__main__":
    # reset_init_for_testing() #add back in to create an empty json when testing
    main()





