import socket
import threading
import json
import datetime
import hashlib 
import os 
import base64
import uuid


from crypto_utils import *
from message_types import MESSAGE_TYPES, parse_message, create_message

# Global variables for round management
current_round = 1
inboxes = {}  # Dictionary to store all user inboxes
#keeps track of the roles of each person
roles = {}

#initialize audit_log

audit_log = []




# from crypto_utils import *


# checks for valid registration, returns Boolean
# assume at the end, will be hashed and salted 
def validate_login(username, hashed_password_try): 
    # retrieve the salt - when we implement hashing and salting
    saved_salt = None
    # retrieve the actual master password from the json file 
    with open('store.json', 'r') as file:
        data = json.load(file)

    saved_password = data.get(username).get('password') # this is hashed and salted

    # hash and salt the try 
    #hashed_salted_try = hashlib.sha256(saved_salt + hashed_password_try.encode()).hexdigest()

    # compare to the actual master password
    if hashed_password_try == saved_password: 
        return True 
    else: 
        return False 

def log_action(action, token, role, current_round):
    event = {
        "time": datetime.datetime.utcnow().isoformat(),
        "action": action,
        "role": role,
        "user_session_token": token,
        "current_round": current_round
    }
    audit_log.append(event)

    with open("audit_logs.json", "w") as file:
        json.dump(audit_log, file)
# Get the public key for a registered user
def get_public_key(username): 
    public_key = None
    # json file entries: {username, public_key}
    with open('public_keys.json', 'r') as file:
        data = json.load(file)
    
    # looks up in the json file and retrieves 
    public_key = data.get(username)

    return public_key

#for the admin to assign roles
def assign_role(admin, user, assigned_role):
    if roles.get(admin) != "Admin":
        print(f"{admin} is not the actual admin and cannot assign roles.")
        return

    roles[user] = assigned_role
    print(f"{user} is now assigned the role of {assigned_role}")

def handle_request(request_data):
    """ 
    Handles a request from the client. Requests are in the form of dictionary. The output of the the function
    is the string response that the server should send back to the client.
    """
    try:
        request = eval(request_data)
        request_type = request.get('type')
        
        if request_type == 'get_public_key':
            username = request.get('username')
            if not username:
                return str({'error': 'Username not provided'})
            
            public_key = get_public_key(username)
            if public_key:
                return str({'type': 'public_key', 'key': public_key})
            else:
                return str({'error': 'Public key not found'})
                
        elif request_type == 'send_message':
            recipient = request.get('recipient')
            encrypted_message = request.get('message')
            
            if not recipient or not encrypted_message:
                return str({'error': 'Missing recipient or message'})
            
            # Store the encrypted message in the recipient's inbox
            try:
                with open('messages.json', 'r') as f:
                    messages = json.load(f)
            except (FileNotFoundError, json.JSONDecodeError):
                messages = {}
            
            if recipient not in messages:
                messages[recipient] = []
            
            messages[recipient].append(encrypted_message)
            
            with open('messages.json', 'w') as f:
                json.dump(messages, f)
            
            return str({'type': 'success', 'message': 'Message stored successfully'})
            
        else:
            return str({'error': 'Invalid request type'})
            
    except Exception as e:
        return str({'error': f'Invalid request format: {str(e)}'})

# saves public key to the public_key.json file 
def store_public_key(username, public_key): 
    # json file entries: {username, public_key}
    with open('public_keys.json', 'r') as file:
        data = json.load(file)
    
    # enters in a new public key for a specified user
    data[username] = public_key

    # write into json file 
    with open('public_keys.json', 'w') as file: 
        json.dump(data, file)

def initialize_inbox(username):
    """Initialize an inbox for a new user"""
    if username not in inboxes:
        inboxes[username] = {}

def store_message(recipient, ciphertext, round_number):
    """Store a message in the recipient's inbox for a specific round"""
    # Initialize recipient's inbox if it doesn't exist
    initialize_inbox(recipient)
    
    # Initialize round in recipient's inbox if it doesn't exist
    if str(round_number) not in inboxes[recipient]:
        inboxes[recipient][str(round_number)] = []
    
    # Add message to the round's list
    message_id = str(uuid.uuid4())  # Generate unique message ID
    message_data = {
        'id': message_id,
        'content': ciphertext,
        'timestamp': str(uuid.uuid1())  # Using UUID1 for timestamp-based ID
    }
    
    inboxes[recipient][str(round_number)].append(message_data)
    
    # Save to persistent storage
    save_inboxes()
    return message_id

def save_inboxes():
    """Save inboxes to persistent storage"""
    with open('inboxes.json', 'w') as f:
        json.dump(inboxes, f)

def load_inboxes():
    """Load inboxes from persistent storage"""
    global inboxes
    try:
        with open('inboxes.json', 'r') as f:
            inboxes = json.load(f)
    except FileNotFoundError:
        inboxes = {}

def get_user_messages(username, round_number):
    """Retrieve messages for a user from a specific round"""
    initialize_inbox(username)
    return inboxes[username].get(str(round_number), [])

def begin_round():
    """Start a new round"""
    global current_round
    current_round += 1
    print(f"Starting round {current_round}")
    return current_round

def get_current_round():
    """Get the current round number"""
    return current_round

def send_message(sender, recipient, ciphertext):
    global active_tokens, current_round
    token = active_tokens.get(sender)

    #maybe want to add some type of check for the role, like if role isn't sender then we say they cant send message
    if not token: #meaning its null or None or something so there's no token for the sender
        print(f"{sender} does not have any remaining tokens for this round")
        return
    #get message and puts it in the inbox of the recipient
    message_id = store_message(recipient, ciphertext, current_round)

    active_tokens[sender] = None #revokes tokens from the sender
    print(f"{sender} has sent a message to {recipient}. Now {sender} has no remaining tokens.")
    log_action("user sent a message", active_tokens[sender], "Sender", current_round)
    return message_id



def end_round():
    global active_tokens
    active_tokens = {} #revokes tokens and resets list to empty for next round
    print("Round has ended. Tokens have been revoked")



# connecting clients 
def handle_client(conn, address):
    print(f"new connection from client {address}")
    while True:
        try:
            # receive data from client
            data = conn.recv(1024).decode()
            if not data:
                break
                

            # Parse the message
            message_type, message_data = parse_message(data)
            if not message_type:
                response = create_message('ERROR', {'error': 'Invalid message format'})
                conn.send(response.encode())
                continue

            # Handle different message types
            if message_type == MESSAGE_TYPES['SEND_MESSAGE']:
                sender = message_data.get('sender')
                recipient = message_data.get('recipient')
                content = message_data.get('content')
                if all([sender, recipient, content]):
                    message_id = store_message(recipient, content, current_round)
                    response = create_message('SUCCESS', {
                        'status': 'Message stored successfully',
                        'message_id': message_id
                    })
                else:
                    response = create_message('ERROR', {'error': 'Missing required fields'})

            elif message_type == MESSAGE_TYPES['REQUEST_MESSAGES']:
                username = message_data.get('username')
                round_number = message_data.get('round_number')
                if username and round_number:
                    messages = get_user_messages(username, round_number)
                    response = create_message('SUCCESS', {
                        'messages': messages,
                        'round_number': round_number
                    })
                else:
                    response = create_message('ERROR', {'error': 'Missing required fields'})

            elif message_type == MESSAGE_TYPES['FLAG_MESSAGE']:
                message_id = message_data.get('message_id')
                reason = message_data.get('reason')
                if message_id and reason:
                    # Store flag information
                    flag_data = {
                        'message_id': message_id,
                        'reason': reason,
                        'timestamp': str(uuid.uuid1())
                    }
                    # You might want to store flags in a separate file
                    with open('flags.json', 'a') as f:
                        json.dump(flag_data, f)
                        f.write('\n')
                    response = create_message('SUCCESS', {'status': 'Message flagged for review'})
                else:
                    response = create_message('ERROR', {'error': 'Missing required fields'})

            elif message_type == MESSAGE_TYPES['REVIEW_MESSAGE']:
                message_id = message_data.get('message_id')
                action = message_data.get('action')
                if message_id and action in ['approve', 'reject']:
                    # Implement review logic here
                    response = create_message('SUCCESS', {'status': f'Message {action}ed'})
                else:
                    response = create_message('ERROR', {'error': 'Invalid review action'})

            else:
                response = create_message('ERROR', {'error': 'Unknown message type'})

            # Send response back to client
            conn.send(response.encode())

        except Exception as e:
            print(f"Error handling client {address}: {str(e)}")

            print(f"Received from {address}: {data}")
            
            # handle the request and get response
            response = handle_request(data)
            
            # send response back to client
            conn.send(response.encode())
            
        except Exception as e:
            print(f"Error handling client {address}: {e}")
            break
    
    print(f"connection from client {address} closed")
    conn.close()

def main():
    # Load existing inboxes when server starts
    load_inboxes()
    
    print("server is running")
    # get the hostname
    host = socket.gethostname()
    port = 5001  #pick a port above 1000 so not conflicting 
    
    # create a socket object
    server_socket = socket.socket()
    server_socket.bind((host, port)) 
    server_socket.listen(8) # allow max 8 connections
    
    print(f"server running on host {host} and port {port}")
    
    while True:
        # accept new connection
        conn, address = server_socket.accept()
        # create a new thread to accept the client
        client_thread = threading.Thread(target=handle_client, args=(conn, address))
        client_thread.start()

if __name__ == "__main__":
    main()

    