import socket
import threading
import json
import time
import random
import string
from datetime import datetime
from message_types import MESSAGE_TYPES, parse_message, create_message
import hashlib 
import os 
import base64
import uuid

from audit_logger import AuditLogger
# from crypto_utils import *


# Initialize audit logger
audit_logger = AuditLogger("server_audit.json")

def generate_token():
    """Generate a random token"""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=16))

def generate_anonymous_id():
    """Generate a random anonymous ID"""
    return f"anon_{''.join(random.choices(string.ascii_letters + string.digits, k=6))}"

# Load data from JSON file
def load_data():
    try:
        with open('data.json', 'r') as f:
            data = json.load(f)
            # Ensure moderator_queue exists
            if "moderator_queue" not in data:
                data["moderator_queue"] = []
            # Ensure flagged_messages is a dictionary
            if "flagged_messages" not in data:
                data["flagged_messages"] = {}
            elif isinstance(data["flagged_messages"], list):
                # Convert list to dictionary if needed
                data["flagged_messages"] = {}
            save_data(data)
            return data
    except FileNotFoundError:
        print("data.json not found, creating new data structure")
        new_data = {
            "users": {},
            "current_round": 1,
            "round_tokens": {},
            "used_tokens": [],
            "banned_tokens": [],
            "messages": {},
            "flagged_messages": {},  # Initialize as empty dictionary
            "encrypted_inboxes": {},
            "moderator_queue": []
        }
        save_data(new_data)
        return new_data
    except json.JSONDecodeError:
        print("Error: data.json is corrupted, creating new data structure")
        new_data = {
            "users": {},
            "current_round": 1,
            "round_tokens": {},
            "used_tokens": [],
            "banned_tokens": [],
            "messages": {},
            "flagged_messages": {},  # Initialize as empty dictionary
            "encrypted_inboxes": {},
            "moderator_queue": []
        }
        save_data(new_data)
        return new_data

# Save data to JSON file
def save_data(data):
    with open('data.json', 'w') as f:
        json.dump(data, f, indent=4)

# Global data
data = load_data()

# Global variables for round management
current_round = 1
inboxes = {}  # Dictionary to store all user inboxes

def add_to_moderator_queue(message_data):
    """Add a flagged message to the global moderator queue"""
    try:
        data["moderator_queue"].append(message_data)
        save_data(data)
        return True
    except Exception as e:
        print(f"Error adding to moderator queue: {str(e)}")
        return False

def get_moderator_queue():
    """Get all messages in the moderator queue"""
    try:
        return data.get("moderator_queue", [])
    except Exception as e:
        print(f"Error getting moderator queue: {str(e)}")
        return []

def block_user(username):
    """Block a user from sending messages"""
    try:
        if username in data["users"]:
            data["users"][username]["is_banned"] = True
            save_data(data)
            return True
        return False
    except Exception as e:
        print(f"Error blocking user: {str(e)}")
        return False

def handle_client(conn, address):
    """Handle client connection"""
    client_session_id = str(uuid.uuid4())
    
    # Log new connection
    audit_logger.log_security_event(
        event_type="CLIENT_CONNECT",
        username="unknown",
        success=True,
        details=f"New client connection from {address[0]}",
        session_id=client_session_id,
        role="unknown"
    )
    
    try:
        while True:
            try:
                # Receive message
                raw_data = conn.recv(1024).decode()
                if not raw_data:
                    break
                    
                print(f"\n=== Server Received ===")
                print(f"Raw data: {raw_data}")
                print("=====================\n")
                
                # Parse message
                message_type, message_data = parse_message(raw_data)
                if not message_type:
                    response = create_message("ERROR", {"error": "Invalid message format"})
                    conn.send(response.encode())
                    continue
                
                # Handle message based on type
                if message_type == "REGISTER":
                    username = message_data.get("username")
                    password = message_data.get("password")
                    
                    audit_logger.log_security_event(
                        event_type="REGISTRATION_ATTEMPT",
                        username=username,
                        success=False,
                        details=f"Registration attempt from {address[0]}",
                        session_id=client_session_id,
                        role="unregistered"
                    )
                    
                    if username == "admin":
                        response = create_message("ERROR", {"error": "Cannot register as admin"})
                    elif username in data["users"]:
                        response = create_message("ERROR", {"error": "Username already exists"})
                    elif username and password:
                        data["users"][username] = {
                            "password": password,
                            "role": "user",
                            "is_banned": False,
                            "anonymous_id": generate_anonymous_id()
                        }
                        
                        audit_logger.log_security_event(
                            event_type="REGISTRATION_SUCCESS",
                            username=username,
                            success=True,
                            details=f"New user registered from {address[0]}",
                            session_id=client_session_id,
                            role="user"
                        )
                        
                        current_round = str(data["current_round"])
                        if current_round not in data["round_tokens"]:
                            data["round_tokens"][current_round] = {}
                        
                        while True:
                            new_token = generate_token()
                            if new_token not in data["used_tokens"] and new_token not in data["banned_tokens"]:
                                data["round_tokens"][current_round][username] = new_token
                                break
                        
                        save_data(data)
                        response = create_message("SUCCESS", {
                            "message": "Registration successful",
                            "token": data["round_tokens"][current_round][username],
                            "round": data["current_round"]
                        })
                    else:
                        response = create_message("ERROR", {"error": "Missing username or password"})
                    
                elif message_type == "LOGIN":
                    username = message_data.get("username")
                    password = message_data.get("password")
                    
                    audit_logger.log_security_event(
                        event_type="LOGIN_ATTEMPT",
                        username=username,
                        success=False,
                        details=f"Login attempt from {address[0]}",
                        session_id=client_session_id,
                        role="unknown"
                    )
                    
                    print(f"\n=== Login Attempt ===")
                    print(f"Username: {username}")
                    print(f"User exists: {username in data['users']}")
                    if username in data["users"]:
                        print(f"Password matches: {data['users'][username]['password'] == password}")
                    print("=====================\n")
                    
                    if username == "admin" and password == "admin123":
                        # Special case for admin
                        audit_logger.log_security_event(
                            event_type="ADMIN_LOGIN",
                            username=username,
                            success=True,
                            details=f"Admin login from IP {address[0]}",
                            session_id=client_session_id,
                            role="admin"
                        )
                        if "admin" not in data["users"]:
                            data["users"]["admin"] = {
                                "password": "admin123",
                                "role": "admin",
                                "anonymous_id": generate_anonymous_id()
                            }
                            save_data(data)
                        response = create_message("SUCCESS", {
                            "message": "Login successful",
                            "role": "admin",
                            "anonymous_id": data["users"]["admin"]["anonymous_id"]
                        })
                    elif username in data["users"] and data["users"][username]["password"] == password:
                        # Generate anonymous ID if user doesn't have one
                        if "anonymous_id" not in data["users"][username]:
                            data["users"][username]["anonymous_id"] = generate_anonymous_id()
                            save_data(data)
                        
                        user_role = data["users"][username]["role"]
                        audit_logger.log_security_event(
                            event_type="LOGIN_SUCCESS",
                            username=username,
                            success=True,
                            details=f"User login from IP {address[0]}",
                            session_id=client_session_id,
                            role=user_role
                        )
                        response = create_message("SUCCESS", {
                            "message": "Login successful",
                            "role": user_role,
                            "anonymous_id": data["users"][username]["anonymous_id"]
                        })
                    else:
                        response = create_message("ERROR", {"error": "Invalid username or password"})
                    conn.settimeout(None)  # No timeout for other operations
                
                elif message_type == MESSAGE_TYPES["GET_TOKEN"]:
                    username = message_data.get("username")
                    current_round = str(data["current_round"])
                    
                    if username in data["users"]:
                        # Initialize round if it doesn't exist
                        if current_round not in data["round_tokens"]:
                            data["round_tokens"][current_round] = {}
                        
                        # Generate new token if user doesn't have one for this round
                        if username not in data["round_tokens"][current_round]:
                            # Generate a new token that hasn't been used
                            while True:
                                new_token = generate_token()
                                if new_token not in data["used_tokens"] and new_token not in data["banned_tokens"]:
                                    data["round_tokens"][current_round][username] = new_token
                                    break
                            save_data(data)
                        
                        # Get the user's token for this round
                        user_token = data["round_tokens"][current_round][username]
                        response = create_message("SUCCESS", {
                            "token": user_token,
                            "round": data["current_round"]
                        })
                    else:
                        response = create_message("ERROR", {"error": "User not found"})
                    
                elif message_type == "SEND_MESSAGE":
                    try:
                        # Set timeout only for long-running operations
                        conn.settimeout(10)  # 10 second timeout for these operations
                        sender = message_data.get("sender")
                        recipient = message_data.get("recipient")
                        content = message_data.get("content")
                        round_token = message_data.get("token")
                        
                        # Add audit log only for the attempt
                        audit_logger.log_event(
                            action="MESSAGE_ATTEMPT",
                            username=sender,
                            role=data["users"][sender]["role"] if sender in data["users"] else "unknown",
                            session_id=client_session_id,
                            token_id=round_token,
                            round_number=data["current_round"]
                        )
                        
                        # Check if sender is admin (admins can't send messages)
                        if data["users"][sender]["role"] == "admin":
                            response = create_message("ERROR", {"error": "Admins cannot send messages"})
                        # Check if sender is banned
                        elif data["users"][sender].get("is_banned", False):
                            response = create_message("ERROR", {"error": "You are banned from sending messages"})
                        # Check if round exists in tokens
                        elif current_round not in data["round_tokens"]:
                            response = create_message("ERROR", {"error": "Invalid round"})
                        # Check if token is valid for this round
                        elif round_token not in data["round_tokens"][current_round].values():
                            response = create_message("ERROR", {"error": "Invalid token"})
                        # Check if token is banned
                        elif round_token in data["banned_tokens"]:
                            response = create_message("ERROR", {"error": "This token has been banned"})
                        # Check if token has already been used
                        elif round_token in data["used_tokens"]:
                            response = create_message("ERROR", {"error": "This token has already been used"})
                        elif all([sender, recipient, content, round_token]):
                            try:
                                # Initialize encrypted_inboxes if it doesn't exist
                                if "encrypted_inboxes" not in data:
                                    data["encrypted_inboxes"] = {}
                                    
                                # Initialize recipient's inbox if it doesn't exist
                                if recipient not in data["encrypted_inboxes"]:
                                    data["encrypted_inboxes"][recipient] = {}
                                
                                # Initialize round in recipient's inbox if it doesn't exist
                                if current_round not in data["encrypted_inboxes"][recipient]:
                                    data["encrypted_inboxes"][recipient][current_round] = []
                                
                                # Generate a unique message ID
                                message_id = f"msg{int(time.time())}"
                                
                                # Create message data
                                message_data = {
                                    "id": message_id,
                                    "message_id": message_id,
                                    "sender": sender,
                                    "sender_anonymous_id": data["users"][sender]["anonymous_id"],
                                    "content": content,
                                    "timestamp": datetime.now().isoformat(),
                                    "is_flagged": False,
                                    "round": current_round,
                                    "round_token": round_token
                                }
                                
                                # Add message to recipient's encrypted inbox
                                data["encrypted_inboxes"][recipient][current_round].append(message_data)
                                
                                # Mark token as used
                                data["used_tokens"].append(round_token)
                                save_data(data)
                                
                                print(f"Message stored successfully in round {current_round}")
                                print(f"Message ID: {message_id}")
                                response = create_message("SUCCESS", {"message": "Message sent", "message_id": message_id})
                            except Exception as e:
                                print(f"Error storing message: {str(e)}")
                                response = create_message("ERROR", {"error": f"Failed to send message: {str(e)}"})
                        else:
                            response = create_message("ERROR", {"error": "Missing required fields"})
                        
                    except Exception as e:
                        print(f"Error in send_message handler: {str(e)}")
                        response = create_message("ERROR", {"error": f"Server error: {str(e)}"})

                elif message_type == MESSAGE_TYPES["REQUEST_MESSAGES"]:
                    username = message_data.get("username")
                    round_number = message_data.get("round_number")
                    
                    print(f"\n=== Requesting Messages ===")
                    print(f"Username: {username}")
                    print(f"Round number: {round_number}")
                    print(f"User exists: {username in data['users']}")
                    print(f"User inbox exists: {username in data['encrypted_inboxes']}")
                    if username in data["encrypted_inboxes"]:
                        print(f"Available rounds: {list(data['encrypted_inboxes'][username].keys())}")
                    print("=====================\n")
                    
                    if username and round_number:
                        try:
                            user_inbox = data["encrypted_inboxes"].get(username, {})
                            round_messages = user_inbox.get(str(round_number), [])
                            print(f"Found {len(round_messages)} messages for round {round_number}")
                            response = create_message("SUCCESS", {
                                "messages": round_messages,
                                "round_number": round_number
                            })
                        except Exception as e:
                            print(f"Error retrieving messages: {str(e)}")
                            response = create_message("ERROR", {"error": f"Failed to retrieve messages: {str(e)}"})
                    else:
                        response = create_message("ERROR", {"error": "Missing username or round number"})
                    
                elif message_type == MESSAGE_TYPES["FLAG_MESSAGE"]:
                    try:
                        username = message_data.get("username")
                        message_id = message_data.get("message_id")
                        reason = message_data.get("reason")
                        
                        # Add audit log for flag attempt
                        audit_logger.log_event(
                            action="FLAG_MESSAGE_ATTEMPT",
                            username=username,
                            role=data["users"][username]["role"] if username in data["users"] else "unknown",
                            session_id=client_session_id,
                            additional_data={"message_id": message_id}
                        )
                        
                        if not all([username, message_id, reason]):
                            print("Missing required fields")
                            response = create_message("ERROR", {"error": "Missing required fields"})
                        elif username not in data["users"]:
                            print(f"Invalid user: {username}")
                            response = create_message("ERROR", {"error": "Invalid user"})
                        else:
                            # Find the message in encrypted inboxes
                            message_found = False
                            flagged_msg = None
                            recipient = None
                            
                            print("Searching for message in encrypted inboxes...")
                            print(f"Current encrypted_inboxes: {json.dumps(data['encrypted_inboxes'], indent=2)}")
                            
                            for rec, inbox in data["encrypted_inboxes"].items():
                                print(f"Checking recipient: {rec}")
                                for round_num, messages in inbox.items():
                                    print(f"Checking round: {round_num}")
                                    for msg in messages:
                                        print(f"Checking message ID: {msg.get('id')} against {message_id}")
                                        if str(msg.get("id")) == str(message_id) or str(msg.get("message_id")) == str(message_id):
                                            message_found = True
                                            flagged_msg = msg
                                            recipient = rec
                                            print(f"Found message: {msg}")
                                            break
                                    if message_found:
                                        break
                                if message_found:
                                    break
                            
                            if not message_found or not flagged_msg:
                                print("Message not found in any inbox")
                                response = create_message("ERROR", {"error": "Message not found"})
                            else:
                                # Create flag entry with all message data
                                flag_entry = {
                                    "message_id": flagged_msg.get("id") or flagged_msg.get("message_id"),
                                    "reason": reason,
                                    "content": flagged_msg["content"],
                                    "sender": flagged_msg.get("sender"),
                                    "sender_anonymous_id": flagged_msg["sender_anonymous_id"],
                                    "timestamp": datetime.now().isoformat(),
                                    "flagged_by": username,
                                    "round": flagged_msg.get("round"),
                                    "round_token": flagged_msg.get("round_token"),
                                    "recipient": recipient,
                                    "original_message": flagged_msg
                                }
                                
                                print(f"Created flag entry: {json.dumps(flag_entry, indent=2)}")
                                
                                # Initialize flagged_messages as a dictionary if it doesn't exist
                                if "flagged_messages" not in data:
                                    print("Initializing flagged_messages dictionary")
                                    data["flagged_messages"] = {}
                                
                                # Add to dictionary using message_id as key
                                data["flagged_messages"][str(message_id)] = flag_entry
                                print(f"Added to flagged_messages. Current dictionary: {json.dumps(data['flagged_messages'], indent=2)}")
                                
                                # Save to data.json
                                save_data(data)
                                print("Saved data to data.json")
                                
                                print(f"Message added to flagged_messages: {flag_entry}")
                                response = create_message("SUCCESS", {"message": "Message flagged successfully"})
                    
                    except Exception as e:
                        print(f"Error in FLAG_MESSAGE handler: {str(e)}")
                        response = create_message("ERROR", {"error": f"Server error: {str(e)}"})

                elif message_type == MESSAGE_TYPES["GET_FLAGGED_MESSAGES"]:
                    username = message_data.get("username")
                    
                    if username and data["users"][username]["role"] == "moderator":
                        flagged_messages = []
                        for msg_id, flag_data in data["flagged_messages"].items():
                            # Find the original message
                            for user_messages in data["messages"].values():
                                for msg in user_messages:
                                    if msg["id"] == msg_id:
                                        flagged_messages.append({
                                            **msg,
                                            "flag_data": flag_data
                                        })
                                        break
                        
                        response = create_message("SUCCESS", {
                            "flagged_messages": flagged_messages
                        })
                    else:
                        response = create_message("ERROR", {"error": "Unauthorized"})
                    
                elif message_type == MESSAGE_TYPES["BAN_TOKEN"]:
                    moderator = message_data.get("moderator")
                    token = message_data.get("token")
                    
                    if moderator and token and data["users"][moderator]["role"] == "moderator":
                        if token not in data["banned_tokens"]:
                            data["banned_tokens"].append(token)
                            save_data(data)
                            response = create_message("SUCCESS", {"message": "Token banned successfully"})
                        else:
                            response = create_message("ERROR", {"error": "Token already banned"})
                    else:
                        response = create_message("ERROR", {"error": "Unauthorized or invalid token"})
                    
                elif message_type == MESSAGE_TYPES["NEXT_ROUND"]:
                    username = message_data.get("username")
                    
                    # Add audit log for round change attempt
                    audit_logger.log_event(
                        action="ROUND_CHANGE_ATTEMPT",
                        username=username,
                        role=data["users"][username]["role"] if username in data["users"] else "unknown",
                        session_id=client_session_id,
                        round_number=data["current_round"]
                    )
                    
                    if username and data["users"][username]["role"] == "admin":
                        data["current_round"] += 1
                        data["round_tokens"][str(data["current_round"])] = {}
                        # Don't clear encrypted inboxes - they persist across rounds
                        save_data(data)
                        
                        # Add audit log for successful round change
                        audit_logger.log_event(
                            action="ROUND_CHANGE_SUCCESS",
                            username=username,
                            role="admin",
                            session_id=client_session_id,
                            round_number=data["current_round"]
                        )
                        
                        response = create_message("SUCCESS", {
                            "message": f"Round {data['current_round']} started",
                            "round": data["current_round"]
                        })
                    else:
                        response = create_message("ERROR", {"error": "Unauthorized"})
                    
                elif message_type == MESSAGE_TYPES["MODERATOR_QUEUE"]:
                    try:
                        username = message_data.get("username")
                        if not username or username not in data["users"]:
                            response = create_message("ERROR", {"error": "Invalid user"})
                        elif data["users"][username]["role"] != "moderator":
                            response = create_message("ERROR", {"error": "Unauthorized - not a moderator"})
                        else:
                            queue = get_moderator_queue()
                            response = create_message("SUCCESS", {"messages": queue})
                        
                    except Exception as e:
                        print(f"Error in MODERATOR_QUEUE handler: {str(e)}")
                        response = create_message("ERROR", {"error": f"Server error: {str(e)}"})
                    
                elif message_type == MESSAGE_TYPES["IGNORE_MESSAGE"]:
                    try:
                        message_id = message_data.get("message_id")
                        
                        print(f"\n=== Ignore Message Request ===")
                        print(f"Message ID: {message_id}")
                        print(f"Message ID type: {type(message_id)}")
                        print(f"Current flagged messages: {json.dumps(data['flagged_messages'], indent=2)}")
                        print("===========================\n")
                        
                        # Validate required fields
                        if not message_id:
                            print("Error: Missing message ID")
                            response = create_message("ERROR", {"error": "Missing message ID"})
                        else:
                            # Convert message_id to string and check existence
                            message_id = str(message_id)
                            print(f"Converted message ID to string: {message_id}")
                            
                            if message_id not in data["flagged_messages"]:
                                print(f"Error: Message {message_id} not found in flagged messages")
                                print(f"Available message IDs: {list(data['flagged_messages'].keys())}")
                                response = create_message("ERROR", {"error": "Message not found in flagged messages"})
                            else:
                                # Remove message from flagged_messages
                                try:
                                    print(f"Attempting to remove message {message_id}")
                                    del data["flagged_messages"][message_id]
                                    print(f"Message removed successfully")
                                    
                                    # Save changes
                                    save_data(data)
                                    print("Changes saved to data.json")
                                    
                                    # Send success response
                                    response = create_message("SUCCESS", {
                                        "message": "Message removed from flagged messages",
                                        "message_id": message_id
                                    })
                                    print(f"Success response created: {response}")
                                    
                                except Exception as e:
                                    print(f"Error processing message: {str(e)}")
                                    print(f"Error type: {type(e)}")
                                    import traceback
                                    print(f"Traceback: {traceback.format_exc()}")
                                    response = create_message("ERROR", {"error": f"Failed to process message: {str(e)}"})
                    
                    except Exception as e:
                        print(f"Error in IGNORE_MESSAGE handler: {str(e)}")
                        print(f"Error type: {type(e)}")
                        import traceback
                        print(f"Traceback: {traceback.format_exc()}")
                        response = create_message("ERROR", {"error": f"Server error: {str(e)}"})

                elif message_type == MESSAGE_TYPES["BLOCK_MESSAGE"]:
                    try:
                        message_id = message_data.get("message_id")
                        username = message_data.get("username")  # This is the moderator's username
                        
                        print(f"\n=== Block Message Request ===")
                        print(f"Message ID: {message_id}")
                        print(f"Moderator: {username}")
                        print(f"Current flagged messages: {json.dumps(data['flagged_messages'], indent=2)}")
                        print("===========================\n")
                        
                        # Validate required fields
                        if not message_id or not username:
                            response = create_message("ERROR", {"error": "Missing required fields"})
                        else:
                            # Get the message from flagged messages
                            message_id = str(message_id)
                            if message_id not in data["flagged_messages"]:
                                response = create_message("ERROR", {"error": "Message not found in flagged messages"})
                            else:
                                # Get the sender's token from the message
                                flagged_message = data["flagged_messages"][message_id]
                                sender_token = flagged_message.get("round_token")
                                
                                if not sender_token:
                                    response = create_message("ERROR", {"error": "Could not find sender's token"})
                                else:
                                    # Add token to banned tokens if not already banned
                                    if "banned_tokens" not in data:
                                        data["banned_tokens"] = []
                                        
                                    if sender_token not in data["banned_tokens"]:
                                        data["banned_tokens"].append(sender_token)
                                        print(f"Token '{sender_token}' added to banned tokens")
                                    
                                    # Remove the message from flagged messages
                                    del data["flagged_messages"][message_id]
                                    print(f"Message '{message_id}' removed from flagged messages")
                                    
                                    # Save changes
                                    save_data(data)
                                    print("Changes saved to data.json")
                                    
                                    # Send success response
                                    response = create_message("SUCCESS", {
                                        "message": "Sender's token blocked and message removed from flagged messages",
                                        "message_id": message_id,
                                        "blocked_token": sender_token
                                    })
                    
                    except Exception as e:
                        print(f"Error in BLOCK_MESSAGE handler: {str(e)}")
                        print(f"Error type: {type(e)}")
                        import traceback
                        print(f"Traceback: {traceback.format_exc()}")
                        response = create_message("ERROR", {"error": f"Server error in BLOCK_MESSAGE: {str(e)}"})

                elif message_type == MESSAGE_TYPES["BLOCK_USER"]:
                    try:
                        username = message_data.get("username")
                        moderator = message_data.get("moderator")
                        
                        # Check if the requester is a moderator
                        if moderator in data["users"] and data["users"][moderator]["role"] == "moderator":
                            if block_user(username):
                                response = create_message("SUCCESS", {"message": f"User {username} has been blocked"})
                            else:
                                response = create_message("ERROR", {"error": "Failed to block user"})
                        else:
                            response = create_message("ERROR", {"error": "Unauthorized: Only moderators can block users"})
                    except Exception as e:
                        print(f"Error in BLOCK_USER handler: {str(e)}")
                        print(f"Error type: {type(e)}")
                        import traceback
                        print(f"Traceback: {traceback.format_exc()}")
                        response = create_message("ERROR", {"error": f"Server error in BLOCK_USER: {str(e)}"})

                elif message_type == MESSAGE_TYPES["GET_MODERATORS"]:
                    username = message_data.get("username")
                    
                    print("\n=== GET_MODERATORS Request ===")
                    print(f"Requesting user: {username}")
                    print(f"User exists: {username in data['users']}")
                    print(f"All users in system: {json.dumps(data['users'], indent=2)}")
                    
                    if username and username in data["users"]:
                        # Get list of all moderators from the data structure
                        moderators = []
                        for uname, user_data in data["users"].items():
                            print(f"\nChecking user: {uname}")
                            print(f"User data: {user_data}")
                            print(f"User role: {user_data.get('role')}")
                            if user_data.get("role") == "moderator":
                                print(f"Found moderator: {uname}")
                                moderators.append(uname)
                        
                        print(f"\n=== Available Moderators ===")
                        print(f"Moderators found: {moderators}")
                        print("===========================\n")
                        
                        # Create response with just the moderators list
                        response = create_message("SUCCESS", {
                            "moderators": moderators
                        })
                    else:
                        response = create_message("ERROR", {"error": "Unauthorized or invalid user"})

                elif message_type == MESSAGE_TYPES["REGISTER"]:
                    username = message_data.get("username")
                    password = message_data.get("password")
                    public_key = message_data.get("public_key")
                    
                    print(f"\n=== Registration Attempt ===")
                    print(f"Username: {username}")
                    print(f"Password: {password}")
                    print(f"User exists: {username in data['users']}")
                    print("========================\n")
                    
                    if not username or not password:
                        response = create_message("ERROR", {"error": "Missing username or password"})
                    elif username in data["users"]:
                        response = create_message("ERROR", {"error": "Username already exists"})
                    else:
                        # Create new user
                        data["users"][username] = {
                            "password": password,
                            "role": "user",  # Default role
                            "anonymous_id": generate_anonymous_id(),
                            "is_banned": False,
                            "public_key": public_key
                        }
                        save_data(data)
                        
                        print(f"New user created: {username}")
                        response = create_message("SUCCESS", {
                            "message": "Registration successful",
                            "role": "user",
                            "anonymous_id": data["users"][username]["anonymous_id"]
                        })

                elif message_type == MESSAGE_TYPES["GET_PUBLIC_KEY"]:
                    recipient = message_data.get("recipient")
                    
                    if recipient in data["users"]:
                        public_key = data["users"][recipient].get("public_key")
                        if public_key:
                            response = create_message("SUCCESS", {
                                "public_key": public_key
                            })
                        else:
                            response = create_message("ERROR", {"error": "User has no public key"})
                    else:
                        response = create_message("ERROR", {"error": "User not found"})
                    
                elif message_type == MESSAGE_TYPES["REVIEW_MESSAGE"]:
                    try:
                        message_id = message_data.get("message_id")
                        action = message_data.get("action")
                        username = message_data.get("username")
                        
                        if not all([message_id, action, username]):
                            response = create_message("ERROR", {"error": "Missing required fields"})
                        elif username not in data["users"]:
                            response = create_message("ERROR", {"error": "Invalid user"})
                        else:
                            # Add audit logging
                            audit_logger.log_event(
                                action="MESSAGE_REVIEW",
                                username=username,
                                role=data["users"][username]["role"] if username in data["users"] else "unknown",
                                session_id=client_session_id,
                                additional_data={"message_id": message_id, "action": action}
                            )
                            
                            # Process the review based on action
                            if action == "approve":
                                # Handle approval logic
                                response = create_message("SUCCESS", {
                                    "message": "Message approved",
                                    "message_id": message_id
                                })
                            elif action == "reject":
                                # Handle rejection logic
                                response = create_message("SUCCESS", {
                                    "message": "Message rejected",
                                    "message_id": message_id
                                })
                            else:
                                response = create_message("ERROR", {"error": "Invalid action"})
                            
                    except Exception as e:
                        print(f"Error in REVIEW_MESSAGE handler: {str(e)}")
                        response = create_message("ERROR", {"error": f"Server error: {str(e)}"})
                    
                elif message_type == MESSAGE_TYPES["APPOINT_MODERATOR"]:
                    admin = message_data.get("admin")
                    target_user = message_data.get("target_user")
                    
                    audit_logger.log_security_event(
                        event_type="MODERATOR_APPOINTMENT_ATTEMPT",
                        username=admin,
                        success=False,
                        details=f"Attempt to appoint {target_user} as moderator",
                        session_id=client_session_id,
                        role=data["users"].get(admin, {}).get("role", "unknown")
                    )
                    
                    if admin and target_user and data["users"][admin]["role"] == "admin":
                        if target_user in data["users"]:
                            if data["users"][target_user]["role"] != "admin":
                                data["users"][target_user]["role"] = "moderator"
                                save_data(data)
                                response = create_message("SUCCESS", {
                                    "message": f"User {target_user} is now a moderator"
                                })
                                
                                audit_logger.log_security_event(
                                    event_type="MODERATOR_APPOINTMENT_SUCCESS",
                                    username=admin,
                                    success=True,
                                    details=f"Successfully appointed {target_user} as moderator",
                                    session_id=client_session_id,
                                    role="admin"
                                )
                            else:
                                response = create_message("ERROR", {"error": "Cannot change admin roles"})
                        else:
                            response = create_message("ERROR", {"error": "Target user not found"})
                    else:
                        response = create_message("ERROR", {"error": "Unauthorized or missing fields"})
                
                else:
                    print(f"Unknown message type: {message_type}")
                    response = create_message("ERROR", {"error": f"Unknown message type: {message_type}"})
                
                # Send response
                print(f"\n=== Server Response ===")
                print(f"Sending: {response}")
                print("=====================\n")
                conn.send(response.encode())
                
                # Reset timeout after sending response
                conn.settimeout(None)
                
            except socket.timeout:
                print(f"Operation timeout for {address}")
                response = create_message("ERROR", {"error": "Operation timed out"})
                try:
                    conn.send(response.encode())
                except:
                    pass
            except Exception as e:
                print(f"Error handling message: {str(e)}")
                response = create_message("ERROR", {"error": f"Server error: {str(e)}"})
                try:
                    conn.send(response.encode())
                except:
                    print("Failed to send error response")
                    
    except Exception as e:
        print(f"Error handling client {address}: {str(e)}")
        audit_logger.log_security_event(
            event_type="CLIENT_ERROR",
            username="unknown",
            success=False,
            details=f"Error handling client: {str(e)}",
            session_id=client_session_id,
            role="unknown"
        )
    finally:
        # Log disconnection
        audit_logger.log_security_event(
            event_type="CLIENT_DISCONNECT",
            username="unknown",
            success=True,
            details=f"Client disconnected from {address[0]}",
            session_id=client_session_id,
            role="unknown"
        )
        conn.close()

def main():
    """Main function to start the server"""
    global server_socket
    
    host = socket.gethostname()
    base_port = 5001
    max_port_attempts = 10
    
    print("Starting WhisperChain server...")
    
    # Log server startup
    audit_logger.log_security_event(
        event_type="SERVER_START",
        username="system",
        success=True,
        details="Server starting up",
        session_id=str(uuid.uuid4()),
        role="system"
    )
    
    # Try different ports if the default one is in use
    for port in range(base_port, base_port + max_port_attempts):
        try:
            server_socket = socket.socket()
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((host, port))
            server_socket.listen(5)
            print(f"Server started successfully on port {port}")
            print(f"Waiting for clients on {host}:{port}...")
            break
        except OSError as e:
            if e.errno == 48:  # Address already in use
                print(f"Port {port} is already in use, trying next port...")
                continue
            else:
                print(f"Error starting server: {e}")
                return
    
    try:
        while True:
            client_socket, address = server_socket.accept()
            print(f"Connection from: {str(address)}")
            # Create a new thread for each client
            client_thread = threading.Thread(
                target=handle_client,
                args=(client_socket, address)
            )
            client_thread.daemon = True
            client_thread.start()
    except KeyboardInterrupt:
        print("\nServer shutting down...")
    finally:
        if server_socket:
            server_socket.close()
            print("Server socket closed.")

if __name__ == "__main__":
    main()

    