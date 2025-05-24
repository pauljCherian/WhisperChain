import json
import base64
import socket
from message_types import *
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
            print("[1] Send a message")
            recipient = input("Recipient username: ")
            message = input("Message: ")
            send_message(recipient, message)
        elif choice == "2":
            print("[2] Retrieve your messages")
            read_messages()
        elif choice == "3":
            print("[3] Flag a message")
            message_id = input("Message ID to flag: ")
            reason = input("Reason for flagging: ")
            flag_message(message_id, reason)
        elif choice == "4":
            print("Goodbye")
            disconnect()
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
        print("[2] Register")
        print("[3] Exit")
        
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
            username = input("Enter desired username: ")
            password = input("Enter password: ")
            if register(username, password):
                print("Registration successful! Please login.")
        elif choice == "3":
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
        
        # Try to send the message, reconnect if needed
        try:
            client_socket.send(message.encode())
        except (BrokenPipeError, ConnectionResetError):
            print("Connection lost. Attempting to reconnect...")
            client_socket = connect_to_server()
            client_socket.send(message.encode())
        
        # Set a timeout for receiving the response
        client_socket.settimeout(10)  # Increased timeout to 10 seconds
        
        try:
            # Get response
            response = client_socket.recv(1024).decode()
            if not response:
                print("No response received from server")
                return False, {"error": "No response from server"}
                
            print(f"Received: {response}")
            
            # Parse response
            response_type, response_data = parse_message(response)
            
            if response_type == ERROR:
                print(f"Error: {response_data.get('error', 'Unknown error')}")
                return False, response_data
                
            return True, response_data
            
        except socket.timeout:
            print("Timeout waiting for server response")
            return False, {"error": "Server response timeout"}
            
    except Exception as e:
        print(f"Error in send_request: {str(e)}")
        return False, {"error": str(e)}
    finally:
        # Reset timeout to blocking mode
        client_socket.settimeout(None)

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
    if not current_user:
        print("Error: You must be logged in to flag messages")
        return False

    print("\n=== Flagging Message ===")
    print(f"Message ID: {message_id}")
    print(f"Reason: {reason}")
    print("=====================\n")

    request_data = {
        "username": current_user,
        "message_id": message_id,
        "reason": reason
    }
    print(f"Sending request: {request_data}")

    success, data = send_request(FLAG_MESSAGE, request_data)
    
    if success:
        print("Message flagged successfully!")
        return True
    else:
        error_msg = data.get('error', 'Unknown error') if isinstance(data, dict) else str(data)
        print(f"Error flagging message: {error_msg}")
        return False

def get_moderator_queue():
    """Get the current moderator's queue from the server"""
    if user_role != "moderator":
        print("Error: Only moderators can access the queue")
        return False

    success, data = send_request(MESSAGE_TYPES["MODERATOR_QUEUE"], {
        "username": current_user
    })
    
    if success:
        global moderator_queue
        moderator_queue = data.get('messages', [])
        return True
    else:
        print(f"Error retrieving moderator queue: {data.get('error', 'Unknown error')}")
        return False

def review_message(message_id, action):
    """Review a flagged message (approve/reject)"""
    if user_role != "moderator":
        print("Error: Only moderators can review messages")
        return False

    if action not in ["approve", "reject"]:
        print("Invalid action. Must be 'approve' or 'reject'")
        return False
        
    success, data = send_request(REVIEW_MESSAGE, {
        "message_id": message_id,
        "action": action,
        "username": current_user
    })
    
    if success:
        if action == "ignore":
            print("Message marked as fine, no action taken")
        elif action == "block":
            print("Sender has been banned")
        else:
            print(f"Message {action}ed successfully!")
        # Update local queue
        get_moderator_queue()
        return True
    else:
        print(f"Error reviewing message: {data.get('error', 'Unknown error')}")
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
    """Read messages from user's inbox"""
    if not current_user:
        print("Not logged in.")
        return False
        
    round_number = input("Enter round number to view messages: ")
    if not round_number:
        print("Round number is required")
        return False
        
    try:
        success, data = send_request(REQUEST_MESSAGES, {
            "username": current_user,
            "round_number": round_number
        })
        
        if success and isinstance(data, dict):
            messages = data.get("messages", [])
            
            if not messages:
                print(f"No messages found for round {round_number}")
                return True
                
            print(f"\nMessages for round {round_number}:")
            for msg in messages:
                print(f"\nMessage ID: {msg['id']}")
                print(f"From: {msg['sender_anonymous_id']}")
                print(f"Content: {msg['content']}")
                print(f"Timestamp: {msg['timestamp']}")
                if msg.get('is_flagged'):
                    print("⚠️ This message has been flagged")
            return True
        else:
            error_msg = data.get("error", "Unknown error") if isinstance(data, dict) else "No response from server"
            print(f"Error: {error_msg}")
            return False
            
    except Exception as e:
        print(f"Error: {str(e)}")
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
    """Display moderator menu and handle moderator actions"""
    while True:
        print("\nModerator Menu:")
        print("[1] View flagged messages")
        print("[2] Return to main menu")
        
        choice = input("Enter your choice (1-2): ")
        
        if choice == "1":
            view_flagged_messages()
        elif choice == "2":
            return
        else:
            print("\nInvalid choice. Please try again.")

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
    if user_role != "moderator":
        print("Only moderators can view flagged messages")
        return
        
    print("\n=== Flagged Messages ===")
    success, data = send_request(MESSAGE_TYPES["GET_FLAGGED_MESSAGES"], {"username": current_user})
        
    if success:
        flagged_messages = data.get("flagged_messages", {})
        if not flagged_messages:
            print("No flagged messages")
            return
                
        for message_id, msg in flagged_messages.items():
            print(f"\nMessage ID: {message_id}")
            print(f"From: {msg.get('sender_anonymous_id', 'Unknown')}")
            print(f"Content: {msg.get('content', 'No content')}")
            print(f"Reason: {msg.get('reason', 'No reason provided')}")
            print(f"Flagged by: {msg.get('flagged_by', 'Unknown')}")
            print(f"Timestamp: {msg.get('timestamp', 'Unknown')}")
            print("-" * 50)
                
        # Ask for action
        while True:
            print("\nOptions:")
            print("1. Ignore flagged message")
            print("2. Block sender's token")
            print("3. Return to main menu")
            
            choice = input("Enter your choice (1-3): ")
            
            if choice == "3":
                break
            elif choice in ["1", "2"]:
                message_id = input("Enter the message ID to take action on: ")
                if message_id in flagged_messages:
                    try:
                        if choice == "1":
                            # Ignore the message
                            success, response = send_request(IGNORE_MESSAGE, {
                                "message_id": message_id
                            })
                            if success:
                                print("Message ignored successfully")
                                # Remove from local view
                                del flagged_messages[message_id]
                            else:
                                error_msg = response.get('error', 'Unknown error') if isinstance(response, dict) else str(response)
                                print(f"Error ignoring message: {error_msg}")
                        elif choice == "2":
                            # Block the sender's token
                            success, response = send_request(BLOCK_MESSAGE, {
                                "message_id": message_id,
                                "username": flagged_messages[message_id].get("sender_anonymous_id", "Unknown")
                            })
                            if success:
                                blocked_token = response.get('blocked_token')
                                print(f"Sender's token blocked successfully: {blocked_token}")
                                # Remove from local view
                                del flagged_messages[message_id]
                            else:
                                error_msg = response.get('error', 'Unknown error') if isinstance(response, dict) else str(response)
                                print(f"Error blocking sender's token: {error_msg}")
                    except Exception as e:
                        print(f"Error processing action: {str(e)}")
                else:
                    print("Invalid message ID")
            else:
                print("Invalid choice")
    else:
        error_msg = data.get('error', 'Unknown error') if isinstance(data, dict) else str(data)
        print(f"Error retrieving flagged messages: {error_msg}")

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

def register(username, password):
    """Register a new user"""
    success, data = send_request(REGISTER, {
        "username": username,
        "password": password
    })
    
    if success:
        print("Registration successful!")
        # Store the token for the current round
        global current_round_token, current_round
        current_round_token = data.get("token")
        current_round = data.get("round")
        print(f"Got round token for round {current_round}")
        return True
    return False

if __name__ == "__main__":
    main()