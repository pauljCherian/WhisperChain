import json
import base64

import socket
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.asymmetric import padding, RSA


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
    
    print("connected to the server")
    return client_socket

def main():
    client_socket = connect_to_server()
    print("connected to the server")
    while True:
        # get message from user to send to the server
        message = input("enter message to send or quit to quit): ")
        
        if message.lower() == 'quit':
            break
        # need to encode the message to send (must be bytes)    
        # send the message to sever
        client_socket.send(message.encode())
        
        # reveive the response from the server, making sure to decode the bytes bak to a string
        response = client_socket.recv(1024).decode()
        print(f"response from server: {response}")
        
    print("disconnected from the server")

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


def send_request_to_server(client_socket,request_type, data=None):
    if data is None:
        data = {}
    #set up the initial dictionary type to send to the server 
    request = {'type': request_type}
    
    #add all pairs from data dictionary to the request dictionary
    for key, value in data.items():
        request[key] = value
    
    # convert the request dict to string, encode it, and then send it to the server
    request_str = str(request)
    client_socket.send(request_str.encode())
    
    # receive and parse response from the server
    response = client_socket.recv(1024).decode()
    return eval(response)  # Convert string representation of dict back to dict

def get_public_key(username):
    response = send_request_to_server('get_public_key', {'username': username})
    
    # if the response is a public key type of message then return the key
    if response.get('type') == 'public_key':
        return response.get('key')
    
    return None

def send_message(message, recipient):
    # Get the recipient's public key
    public_key = get_public_key(recipient)
    if not public_key:
        print(f"Could not get public key for {recipient}")
        return
    
    # Encrypt the message with the recipient's public key
    encrypted_message = encrypt_message(message, public_key)
    
    # Send the encrypted message to the server
    request_data = {
        'type': 'send_message',
        'recipient': recipient,
        'message': encrypted_message
    }
    
    # Send the request to the server
    response = send_request_to_server('send_message', request_data)
    
    if 'error' in response:
        print(f"Error sending message: {response['error']}")
    else:
        print(f"Message sent successfully to {recipient}")

def encrypt_message(message, public_key):
    """
    Encrypt a message using the recipient's public key.
    Returns the encrypted message as a base64 string.
    """
    # Convert the public key from string to RSA key object
    public_key_obj = load_public_key(public_key)
    
    # Encrypt the message
    encrypted = public_key_obj.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Convert the encrypted bytes to base64 string for transmission
    return base64.b64encode(encrypted).decode()

def read_messages():
    pass
    # Asks the server for messages associated with their account
    # (so send their username under the hood)

def disconnect():
    # Tell the server you've disconnected, log out (automatic) 
    pass

if __name__ == "__main__":
    main()