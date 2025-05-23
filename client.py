import json
import base64

import socket
from message_types import MESSAGE_TYPES, create_message, parse_message

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
    # Hash & salt the password

    # Send username and hashed password to the server
    # interacts with validate login function to get 1. Validation and 2. Account category
    
    # return validation, account_cat
    pass 

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

def read_messages():
    """Retrieve and display messages for the current round"""
    if not current_user:
        print("Error: Not logged in")
        return False
 


    # Ask user which round to retrieve messages from
    print("\nAvailable rounds:")
    print("[1] Current round")
    print("[2] Previous round")
    print("[3] Enter specific round number: ")
    
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

def decrypt_message(encrypted_message, private_key):
    # Implement decryption using the private key
    # This is a placeholder - implement your decryption logic here
    return base64.b64decode(encrypted_message.encode()).decode()

def disconnect():
    # Tell the server you've disconnected, log out (automatic) 
    pass

if __name__ == "__main__":
    main()