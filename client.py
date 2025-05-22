import json
import base64
import socket
from message_types import (
    LOGIN, SEND_MESSAGE, REQUEST_MESSAGES, FLAG_MESSAGE,
    GET_FLAGGED_MESSAGES, BAN_USER, MAKE_MODERATOR,
    SUCCESS, ERROR, create_message, parse_message
)
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives import serialization

# Global variables
current_user = None
current_round = 1
client_socket = None
private_key = None
user_role = None  # Store the current user's role

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
    global current_user, user_role
    
    success, data = send_request(LOGIN, {
        "username": username,
        "password": password
    })
    
    if success:
        current_user = username
        user_role = data.get("role")
        print(f"Login successful! Role: {user_role}")
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
    if not current_user:
        print("Not logged in")
        return False
        
    success, data = send_request(SEND_MESSAGE, {
        "sender": current_user,
        "recipient": recipient,
        "content": content
    })
    
    if success:
        print("Message sent successfully")
        return True
    return False

def flag_message(message_id, reason):
    """Flag a message for review"""
    if not current_user:
        print("Not logged in")
        return False
        
    success, data = send_request(FLAG_MESSAGE, {
        "username": current_user,
        "message_id": message_id,
        "reason": reason
    })
    
    if success:
        print("Message flagged successfully")
        return True
    return False

def review_message(message_id, action):
    if action not in ['approve', 'reject']:
        print("Invalid action. Must be 'approve' or 'reject'")
        return False
        
    message_data = {
        'message_id': message_id,
        'action': action
    }
    
    message_str = create_message(REVIEW_MESSAGE, message_data)
    client_socket.send(message_str.encode())
    
    response = client_socket.recv(1024).decode()
    response_type, response_data = parse_message(response)
    
    if response_type == 'SUCCESS':
        print(f"Message {action}ed successfully!")
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
                print(f"Content: {msg.get('content')}")
                print(f"Time: {msg.get('timestamp')}")
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
        print("[1] Make a user a moderator")
        print("[2] Exit")
        
        choice = input("Enter your choice: ")
        
        if choice == "1":
            target_user = input("Username to make moderator: ")
            make_moderator(target_user)
        elif choice == "2":
            print("Goodbye")
            break
        else:
            print("Invalid choice")

def moderator_menu():
    """Menu for moderators"""
    while True:
        print("\nModerator Menu:")
        print("[1] Send a message")
        print("[2] Read messages")
        print("[3] Flag a message")
        print("[4] View flagged messages")
        print("[5] Ban a user")
        print("[6] Exit")
        
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
            view_flagged_messages()
        elif choice == "5":
            target_user = input("Username to ban: ")
            ban_user(target_user)
        elif choice == "6":
            print("Goodbye")
            break
        else:
            print("Invalid choice")

def ban_user(target_user):
    """Ban a user (moderator only)"""
    if not current_user or user_role != "moderator":
        print("Only moderators can ban users")
        return False
        
    success, data = send_request(BAN_USER, {
        "moderator": current_user,
        "target_user": target_user
    })
    
    if success:
        print(f"User {target_user} has been banned")
        return True
    return False

def make_moderator(target_user):
    """Make a user a moderator (admin only)"""
    if not current_user or user_role != "admin":
        print("Only admins can make moderators")
        return False
        
    success, data = send_request(MAKE_MODERATOR, {
        "admin": current_user,
        "target_user": target_user
    })
    
    if success:
        print(f"User {target_user} is now a moderator")
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
                print(f"Content: {msg.get('content')}")
                print(f"Time: {msg.get('timestamp')}")
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

if __name__ == "__main__":
    main()