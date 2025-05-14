import json
import base64

import socket


# helper functions
def write_json(filename, data):
    with open(filename, 'w') as json_file:
        json.dump(data, json_file)

def read_json(filename):
    with open(filename, 'r') as json_file:
        return json.load(json_file)


def connect_to_server():
    # get the hostname
    host = socket.gethostname()
    port = 5001  # server port number

    # create a socket object
    client_socket = socket.socket()
    client_socket.connect((host, port))  # connect to the server
    
    print("Connected to the server")
    return client_socket

def main():
    client_socket = connect_to_server()
    print("Connected to the server")
    while True:
        # get message from user to send to the server
        message = input("Enter message to send or quit to quit): ")
        
        if message.lower() == 'quit':
            break
        # need to encode the message to send (must be bytes)    
        # send the message to sever
        client_socket.send(message.encode())
        
        # reveive the response from the server, making sure to decode the bytes bak to a string
        response = client_socket.recv(1024).decode()
        print(f"Response from server: {response}")
        
    print("Disconnected from the server")

## the menu for if the client is a user
def user_menu():
    while True:
        print("\nWhat would you like to do?")
        print("[1] Send a message")
        print("[2] Retrieve your messages")
        # print("[3] Report a message sender")
        print("[4] Exit the program")
        choice = input("Enter a number: ")
        if choice == "1":
            print("[1] Send a message")
            recipient = input("Who is your message to? ")
            message = input("What is your message? ")
            send_message(message, recipient)
            user_menu()
        elif choice == "2":
            print("[2] Retreive your messages")
            read_messages()
            user_menu()
        # elif choice == "3":
        #     print("[3] Report a message sender")
        #     report_message()
        #     user_menu()
        elif choice == "4":
            print("Goodbye")
            disconnect()
        else:
            print("Invalid entry. Please try again")

def create_account(username, password):
    # Account category is automatically "user"
    account_cat = "user"

    ## generate public/private key pair from a password

    ## store private key locally as a variable

    ## send public key to server

    ##automatically login
    login(username, password)
    # Generates public/private key pair from password
    # Send public key to server
    # Sever calls store_public_key()
    # Hash & store private key
    # Automatically login 

def login(username, password): 
    # Hash & salt the password

    # Send username and hashed password to the server
    # interacts with validate login function to get 1. Validation and 2. Account category
    
    # return validation, account_cat
    pass 

def send_message(message, recipient):
    # Gets the public key from the server
    # Encrypts the message with that public key
    # Sends the encrypted message to the server with the recipient's name attached (for storage in their "inbox") 
    pass

def read_messages():
    pass
    # Asks the server for messages associated with their account
    # (so send their username under the hood)

def disconnect():
    # Tell the server you've disconnected, log out (automatic) 
    pass

if __name__ == "__main__":
    main()