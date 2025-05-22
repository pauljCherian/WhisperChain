import json
import base64
import os

import socket

from message_types import MESSAGE_TYPES, create_message, parse_message

from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.asymmetric import padding, RSA
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# Global variables
current_user = None
current_round = 1
client_socket = None
private_key = None

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
        print("[3] Flag a message")
        print("[4] Exit the program")
        choice = input("Enter a number: ")
        if choice == "1":
            print("[1] Send a message")
            recipient = input("Who is your message to? ")
            message = input("What is your message? ")
            send_message(message, recipient)
        elif choice == "2":
            print("[2] Retrieve your messages")
            read_messages()
        elif choice == "3":
            print("[3] Flag a message")
            message_id = input("Enter the message ID to flag: ")
            reason = input("Enter reason for flagging: ")
            flag_message(message_id, reason)
        elif choice == "4":
            print("Goodbye")
            disconnect()
            break
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
    # Send username and hashed password to the server
    # interacts with validate login function to get 1. Validation and 2. Account categor

    # Hash & salt the password
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    hashed_password = base64.b64encode(kdf.derive(password.encode())).decode()
    
    # Generate RSA key pair
    private_key = RSA.generate_2048()
    public_key = private_key.public_key()
    
    # Store private key in JSON file
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    private_key_b64 = base64.b64encode(private_key_bytes).decode()
    
    credentials = {
        'username': username,
        'private_key': private_key_b64
    }
    write_json('client_credentials.json', credentials)
    
    # Convert public key to base64 for transmission
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    public_key_b64 = base64.b64encode(public_key_bytes).decode()
    
    # Send login request to server
    login_data = {
        'username': username,
        'password': hashed_password,
        'public_key': public_key_b64
    }
    
    response = send_request_to_server(client_socket, 'login', login_data)
    
    # talk to server, return validation, account_cat
    if response.get('type') == 'SUCCESS':
        global current_user
        current_user = username
        print(f"Successfully logged in as {username}")
        return True, response.get('account_cat')
    else:
        print(f"Login failed: {response.get('error', 'Unknown error')}")
        return False, None

def load_private_key():
    # Load the private key from the credentials file
    try:
        credentials = read_json('client_credentials.json')
        private_key_b64 = credentials['private_key']
        private_key_bytes = base64.b64decode(private_key_b64)
        return serialization.load_der_private_key(
            private_key_bytes,
            password=None
        )
    except Exception as e:
        print(f"Error loading private key: {str(e)}")
        return None

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

    # Get the public key from the server
    public_key = get_public_key(recipient)
    if not public_key:
        print("Error: Could not retrieve recipient's public key")
        return False

    # Encrypt the message with the recipient's public key
    encrypted_message = encrypt_message(message, public_key)
    
    # Create the message data
    message_data = {
        'sender': current_user,  # You'll need to track the current user
        'recipient': recipient,
        'content': encrypted_message
    }
    
    # Send the message to the server
    message_str = create_message(MESSAGE_TYPES['SEND_MESSAGE'], message_data)
    client_socket.send(message_str.encode())
    
    # Get response from server
    response = client_socket.recv(1024).decode()
    response_type, response_data = parse_message(response)
    
    if response_type == 'SUCCESS':
        print("Message sent successfully!")
        return True
    else:
        print(f"Error sending message: {response_data.get('error', 'Unknown error')}")
        return False

def flag_message(message_id, reason):
    message_data = {
        'message_id': message_id,
        'reason': reason
    }
    
    message_str = create_message(MESSAGE_TYPES['FLAG_MESSAGE'], message_data)
    client_socket.send(message_str.encode())
    
    response = client_socket.recv(1024).decode()
    response_type, response_data = parse_message(response)
    
    if response_type == 'SUCCESS':
        print("Message flagged successfully!")
        return True
    else:
        print(f"Error flagging message: {response_data.get('error', 'Unknown error')}")
        return False

def review_message(message_id, action):
    if action not in ['approve', 'reject']:
        print("Invalid action. Must be 'approve' or 'reject'")
        return False
        
    message_data = {
        'message_id': message_id,
        'action': action
    }
    
    message_str = create_message(MESSAGE_TYPES['REVIEW_MESSAGE'], message_data)
    client_socket.send(message_str.encode())
    
    response = client_socket.recv(1024).decode()
    response_type, response_data = parse_message(response)
    
    if response_type == 'SUCCESS':
        print(f"Message {action}ed successfully!")
        return True
    else:
        print(f"Error reviewing message: {response_data.get('error', 'Unknown error')}")
        return False
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

def decrypt_message(encrypted_message, private_key=None):
    # Decrypt a message using the private key.
    # If private_key is not provided, it will be loaded from the credentials file.
    if private_key is None:
        private_key = load_private_key()
        if private_key is None:
            raise ValueError("Could not load private key")
    
    try:
        # Decode the base64 message
        encrypted_bytes = base64.b64decode(encrypted_message)
        
        # Decrypt the message
        decrypted = private_key.decrypt(
            encrypted_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return decrypted.decode()
    except Exception as e:
        raise ValueError(f"Decryption failed: {str(e)}")

def read_messages():
    """Retrieve and display messages for the current round"""
    if not current_user:
        print("Error: Not logged in")
        return False

    # Load private key for decryption
    private_key = load_private_key()
    if private_key is None:
        print("Error: Could not load private key")
        return False

    # Ask user which round to retrieve messages from
    print("\nAvailable rounds:")
    print("[1] Current round")
    print("[2] Previous round")
    print("[3] Enter specific round number")
    
    choice = input("Enter your choice (1-3): ")
    
    if choice == "1":
        round_number = current_round
    elif choice == "2":
        round_number = current_round - 1
    elif choice == "3":
        try:
            round_number = int(input("Enter round number: "))
        except ValueError:
            print("Invalid round number")
            return False
    else:
        print("Invalid choice")
        return False

    message_data = {
        'username': current_user,
        'round_number': round_number
    }
    
    message_str = create_message(MESSAGE_TYPES['REQUEST_MESSAGES'], message_data)
    client_socket.send(message_str.encode())
    
    response = client_socket.recv(1024).decode()
    response_type, response_data = parse_message(response)
    
    if response_type == 'SUCCESS':
        messages = response_data.get('messages', [])
        if not messages:
            print(f"\nNo messages found for round {round_number}.")
        else:
            print(f"\nMessages from round {round_number}:")
            for msg in messages:
                try:
                    # Decrypt and display each message
                    decrypted_msg = decrypt_message(msg['content'], private_key)
                    print(f"\nMessage ID: {msg['id']}")
                    print(f"Timestamp: {msg['timestamp']}")
                    print(f"Content: {decrypted_msg}")
                    print("-" * 50)
                except Exception as e:
                    print(f"Error decrypting message: {str(e)}")
        return True
    else:
        print(f"Error retrieving messages: {response_data.get('error', 'Unknown error')}")
        return False

def encrypt_message(message, public_key):
    # Implement encryption using the public key
    # This is a placeholder - implement your encryption logic here
    return base64.b64encode(message.encode()).decode()

def disconnect():
    # Tell the server you've disconnected, log out (automatic) 
    pass

if __name__ == "__main__":
    main()