import json
import base64
import socket
from message_types import (
    LOGIN, SEND_MESSAGE, REQUEST_MESSAGES, FLAG_MESSAGE,
    GET_FLAGGED_MESSAGES, BAN_TOKEN, GET_TOKEN, NEXT_ROUND,
    SUCCESS, ERROR, create_message, parse_message, MESSAGE_TYPES
)
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives import serialization

# Global variables
current_user = None
user_role = None
client_socket = None
current_round_token = None
current_anonymous_id = None
current_round = 1
private_key = None
is_moderator = False
moderator_queue = []  # Local queue for moderator messages

# helper functions
def write_json(filename, data):
    with open(filename, 'w') as json_file:
        json.dump(data, json_file)

def read_json(filename):
    with open(filename, 'r') as json_file:
        return json.load(json_file)

def connect_to_server():
    """Connect to the server"""
    host = socket.gethostname()
    port = 5001
    
    client_socket = socket.socket()
    client_socket.connect((host, port))
    print("Connected to server")
    return client_socket

def load_user_role(username):
    """Load user role from roles.json"""
    try:
        with open('roles.json', 'r') as f:
            roles = json.load(f)
            return roles.get(username, "user")  # Default to "user" if role not found
    except FileNotFoundError:
        return "user"  # Default to "user" if file not found

def login(username, password):
    """Login to the system"""
    global current_user, user_role, current_anonymous_id
    
    success, data = send_request(LOGIN, {
        "username": username,
        "password": password
    })
    
    if success:
        current_user = username
        user_role = data.get("role")
        current_anonymous_id = data.get("anonymous_id")
        print(f"Login successful! Role: {user_role}")
        print(f"Your anonymous ID: {current_anonymous_id}")
        # Get token for current round
        get_round_token()
        return True
    return False

def create_account(username, password):
    """Create a new account"""
    # Hash & salt the password (placeholder for actual implementation)
    hashed_password = password  # Replace with actual hashing
    
    # Generate key pair
    global private_key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    
    # Send account creation request to server
    request_data = {
        'type': 'create_account',
        'username': username,
        'password': hashed_password,
        'public_key': public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
    }
    
    response = send_request("LOGIN", request_data)
    
    if response.get('type') == 'success':
        print("Account created successfully")
        # Automatically login
        return login(username, password)
    else:
        print(f"Account creation failed: {response.get('error', 'Unknown error')}")
        return False

def user_menu():
    """Main menu for regular users"""
    while True:
        print("\nUser Menu:")
        print("[1] Send a message")
        print("[2] Read messages")
        print("[3] Flag a message")
        print("[4] Exit")
        
        choice = input("Enter your choice: ")
        
        if choice == "1":
            recipient = input("Recipient username: ")
            message = input("Message: ")
            send_message(recipient, message)
        elif choice == "2":
            read_messages()
        elif choice == "3":
            message_id = input("Message ID to flag: ")
            reason = input("Reason for flagging: ")
            flag_message(message_id, reason)
        elif choice == "4":
            print("Goodbye")
            break
        else:
            print("Invalid choice")

def main():
    """Main function to start the client"""
    global client_socket
    client_socket = connect_to_server()
    
    while True:
        print("\nWelcome to the Secure Messaging System")
        print("[1] Login")
        print("[2] Exit")
        
        choice = input("Enter your choice: ")
        
        if choice == "1":
            username = input("Enter username: ")
            password = input("Enter password: ")
            if login(username, password):
                if user_role == "admin":
                    admin_menu()
                elif user_role == "moderator":
                    moderator_menu()
                else:
                    user_menu()
        elif choice == "2":
            print("Goodbye")
            break
        else:
            print("Invalid choice")
    
    if client_socket:
        client_socket.close()

def send_request(request_type, data=None):
    """Send a request to the server and get response"""
    global client_socket
    
    if data is None:
        data = {}
    
    try:
        # Create and send message
        message = create_message(request_type, data)
        print(f"Sending: {message}")
        client_socket.send(message.encode())
        
        # Get response
        response = client_socket.recv(1024).decode()
        print(f"Received: {response}")
        
        # Parse response
        response_type, response_data = parse_message(response)
        
        if response_type == ERROR:
            print(f"Error: {response_data.get('error', 'Unknown error')}")
            return False, response_data.get('error', 'Unknown error')
            
        return True, response_data
        
    except Exception as e:
        print(f"Error in send_request: {str(e)}")
        return False, str(e)

def get_public_key(username):
    response = send_request("LOGIN", {'username': username})
    
    # if the response is a public key type of message then return the key
    if response.get('type') == 'public_key':
        return response.get('key')
    
    return None

def send_message(recipient, content):
    """Send a message to another user"""
    global current_round_token
    
    if not current_user:
        print("Not logged in")
        return False
        
    if not current_round_token:
        print("No round token available. Getting new token...")
        if not get_round_token():
            return False
        
    success, data = send_request(SEND_MESSAGE, {
        "sender": current_user,
        "recipient": recipient,
        "content": content,
        "token": current_round_token
    })
    
    if success:
        print("Message sent successfully")
        current_round_token = None  # Token used, clear it
        return True
    return False

def flag_message(message_id, reason):
    """Flag a message for moderator review"""
    if not is_moderator:
        print("Error: Only moderators can flag messages")
        return False

    message_data = {
        'message_id': message_id,
        'reason': reason,
        'moderator': current_user
    }
    
    message_str = create_message(MESSAGE_TYPES['MODERATOR_FLAG'], message_data)
    client_socket.send(message_str.encode())
    
    response = client_socket.recv(1024).decode()
    response_type, response_data = parse_message(response)
    
    if response_type == 'SUCCESS':
        print("Message flagged successfully!")
        return True
    else:
        print(f"Error flagging message: {response_data.get('error', 'Unknown error')}")
        return False

def get_moderator_queue():
    """Get the current moderator's queue from the server"""
    if not is_moderator:
        print("Error: Only moderators can access the queue")
        return False

    message_data = {
        'moderator': current_user
    }
    
    message_str = create_message(MESSAGE_TYPES['MODERATOR_QUEUE'], message_data)
    client_socket.send(message_str.encode())
    
    response = client_socket.recv(1024).decode()
    response_type, response_data = parse_message(response)
    
    if response_type == 'SUCCESS':
        global moderator_queue
        moderator_queue = response_data.get('messages', [])
        return True
    else:
        print(f"Error retrieving moderator queue: {response_data.get('error', 'Unknown error')}")
        return False

def review_message(message_id, action):
    """Review a flagged message (approve/reject)"""
    if not is_moderator:
        print("Error: Only moderators can review messages")
        return False

    if action not in ['approve', 'reject']:
        print("Invalid action. Must be 'approve' or 'reject'")
        return False
        
    message_data = {
        'message_id': message_id,
        'action': action,
        'moderator': current_user
    }
    
    message_str = create_message(MESSAGE_TYPES['REVIEW_MESSAGE'], message_data)
    client_socket.send(message_str.encode())
    
    response = client_socket.recv(1024).decode()
    response_type, response_data = parse_message(response)
    
    if response_type == 'SUCCESS':
        print(f"Message {action}ed successfully!")
        # Update local queue
        get_moderator_queue()
        return True
    else:
        print(f"Error reviewing message: {response_data.get('error', 'Unknown error')}")
        return False

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
    """Read messages for the current user"""
    if not current_user:
        print("Not logged in")
        return False
        
    success, data = send_request(REQUEST_MESSAGES, {
        "username": current_user
    })
    
    if success:
        messages = data.get("messages", [])
        if messages:
            print("\nYour messages:")
            for msg in messages:
                print(f"\nFrom: {msg.get('sender')}")
                print(f"Anonymous ID: {msg.get('sender_anonymous_id')}")
                print(f"Content: {msg.get('content')}")
                print(f"Time: {msg.get('timestamp')}")
                print(f"Round: {msg.get('round')}")
                if msg.get('is_flagged'):
                    print("⚠️ This message has been flagged")
                print("-" * 50)
        else:
            print("No messages found")
        return True
    return False

def decrypt_message(encrypted_message, private_key):
    # Implement decryption using the private key
    # This is a placeholder - implement your decryption logic here
    return base64.b64decode(encrypted_message.encode()).decode()

def disconnect():
    # Tell the server you've disconnected, log out (automatic) 
    pass

def admin_menu():
    """Menu for admins"""
    while True:
        print("\nAdmin Menu:")
        print("[1] Start new round")
        print("[2] Appoint moderator")
        print("[3] Exit")
        
        choice = input("Enter your choice: ")
        
        if choice == "1":
            start_new_round()
        elif choice == "2":
            target_user = input("Username to make moderator: ")
            appoint_moderator(target_user)
        elif choice == "3":
            print("Goodbye")
            break
        else:
            print("Invalid choice")

def appoint_moderator(target_user):
    """Appoint a user as moderator (admin only)"""
    if not current_user or user_role != "admin":
        print("Only admins can appoint moderators")
        return False
        
    success, data = send_request(APPOINT_MODERATOR, {
        "admin": current_user,
        "target_user": target_user
    })
    
    if success:
        print(f"User {target_user} is now a moderator")
        return True
    return False

def moderator_menu():
    """Menu for moderator actions"""
    while True:
        print("\nModerator Menu:")
        print("[1] View flagged messages")
        print("[2] Review a message")
        print("[3] Return to main menu")
        
        choice = input("Enter your choice (1-3): ")
        
        if choice == "1":
            if get_moderator_queue():
                if not moderator_queue:
                    print("No flagged messages in queue")
                else:
                    print("\nFlagged Messages:")
                    for msg in moderator_queue:
                        print(f"\nMessage ID: {msg['message_id']}")
                        print(f"From: {msg['sender']}")
                        print(f"Round: {msg['round_number']}")
                        print(f"Reason: {msg['reason']}")
                        print(f"Timestamp: {msg['timestamp']}")
                        print("-" * 50)
        
        elif choice == "2":
            if not moderator_queue:
                print("No messages to review")
                continue
                
            message_id = input("Enter message ID to review: ")
            action = input("Enter action (approve/reject): ").lower()
            review_message(message_id, action)
        
        elif choice == "3":
            break
        
        else:
            print("Invalid choice")

def ban_token(token):
    """Ban a token (moderator only)"""
    if not current_user or user_role != "moderator":
        print("Only moderators can ban tokens")
        return False
        
    success, data = send_request(BAN_TOKEN, {
        "moderator": current_user,
        "token": token
    })
    
    if success:
        print("Token banned successfully")
        return True
    return False

def start_new_round():
    """Start a new round (admin only)"""
    if not current_user or user_role != "admin":
        print("Only admins can start new rounds")
        return False
        
    success, data = send_request(NEXT_ROUND, {
        "username": current_user
    })
    
    if success:
        print(f"Round {data.get('round')} started")
        return True
    return False

def view_flagged_messages():
    """View flagged messages (moderator only)"""
    if not current_user or user_role != "moderator":
        print("Only moderators can view flagged messages")
        return False
        
    success, data = send_request(GET_FLAGGED_MESSAGES, {
        "username": current_user
    })
    
    if success:
        flagged_messages = data.get("flagged_messages", [])
        if flagged_messages:
            print("\nFlagged Messages:")
            for msg in flagged_messages:
                print(f"\nMessage ID: {msg.get('id')}")
                print(f"From: {msg.get('sender')}")
                print(f"Anonymous ID: {msg.get('sender_anonymous_id')}")
                print(f"Content: {msg.get('content')}")
                print(f"Time: {msg.get('timestamp')}")
                print(f"Round: {msg.get('round')}")
                print(f"Round Token: {msg.get('round_token')}")
                print(f"Flagged by: {msg.get('flag_data', {}).get('flagged_by')}")
                print(f"Reason: {msg.get('flag_data', {}).get('reason')}")
                print("-" * 50)
        else:
            print("No flagged messages found")
        return True
    return False

def view_audit_log():
    """View audit log (moderator only)"""
    request_data = {
        'type': 'view_audit_log',
        'username': current_user
    }
    
    response = send_request("LOGIN", request_data)
    if 'error' in response:
        print(f"Error: {response['error']}")
        return False
        
    log_entries = response.get('log', [])
    if not log_entries:
        print("No audit log entries found")
        return True
        
    print("\nAudit Log:")
    for entry in log_entries:
        print(f"\nTimestamp: {entry.get('timestamp')}")
        print(f"Action: {entry.get('action')}")
        print(f"User: {entry.get('username')}")
        print(f"Role: {entry.get('role')}")
        print(f"Round: {entry.get('round')}")
        print("-" * 50)
    return True

def view_all_users():
    """View all users in the system (admin only)"""
    request_data = {
        'type': 'view_all_users',
        'username': current_user
    }
    
    response = send_request("LOGIN", request_data)
    if 'error' in response:
        print(f"Error: {response['error']}")
        return False
        
    users = response.get('users', {})
    if not users:
        print("No users found")
        return True
        
    print("\nSystem Users:")
    for username, role in users.items():
        print(f"{username}: {role}")
    return True

def get_round_token():
    """Get a round token for the current round"""
    global current_round_token, current_round
    
    success, data = send_request(GET_TOKEN, {
        "username": current_user
    })
    
    if success:
        current_round_token = data.get("token")
        current_round = data.get("round")
        print(f"Got round token for round {current_round}")
        return True
    return False

if __name__ == "__main__":
    main()