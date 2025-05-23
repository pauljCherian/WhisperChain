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
            return json.load(f)
    except FileNotFoundError:
        print("data.json not found, creating new data structure")
        return {
            "users": {},
            "current_round": 1,
            "round_tokens": {},
            "used_tokens": [],
            "banned_tokens": [],
            "messages": {},
            "flagged_messages": {}
        }

# Save data to JSON file
def save_data(data):
    with open('data.json', 'w') as f:
        json.dump(data, f, indent=4)

# Global data
data = load_data()

# Global variables for round management
current_round = 1
inboxes = {}  # Dictionary to store all user inboxes
moderator_queues = {}  # Dictionary to store moderator message queues

def initialize_moderator_queue(moderator_name):
    """Initialize a queue for a new moderator"""
    if moderator_name not in moderator_queues:
        moderator_queues[moderator_name] = []

def add_to_moderator_queue(moderator_name, message_data):
    """Add a flagged message to a moderator's queue"""
    initialize_moderator_queue(moderator_name)
    moderator_queues[moderator_name].append(message_data)

def get_moderator_queue(moderator_name):
    """Get all messages in a moderator's queue"""
    initialize_moderator_queue(moderator_name)
    return moderator_queues[moderator_name]

def handle_client(conn, address):
    """Handle client connection"""
    print(f"New connection from {address}")
    
    while True:
        try:
            # Receive message
            raw_data = conn.recv(1024).decode()
            print(f"\n=== Server Received ===")
            print(f"Raw data: {raw_data}")
            print(f"Data type: {type(raw_data)}")
            print("=====================\n")
            
            if not raw_data:
                print("No data received, closing connection")
                break
                
            # Parse message
            message_type, message_data = parse_message(raw_data)
            print("\n=== Parsed Message ===")
            print(f"Message type: {message_type}")
            print(f"Message data: {message_data}")
            print("=====================\n")
            
            if not message_type:
                print("Error: Invalid message format")
                response = create_message("ERROR", {"error": "Invalid message format"})
                conn.send(response.encode())
                continue
            
            # Handle message based on type
            if message_type == MESSAGE_TYPES["LOGIN"]:
                username = message_data.get("username")
                password = message_data.get("password")
                
                print(f"\n=== Login Attempt ===")
                print(f"Username: {username}")
                print(f"Password: {password}")
                print(f"User exists: {username in data['users']}")
                if username in data["users"]:
                    print(f"Password matches: {data['users'][username]['password'] == password}")
                print("=====================\n")
                
                if username in data["users"] and data["users"][username]["password"] == password:
                    # Generate anonymous ID if user doesn't have one
                    if "anonymous_id" not in data["users"][username]:
                        data["users"][username]["anonymous_id"] = generate_anonymous_id()
                        save_data(data)
                    
                    response = create_message("SUCCESS", {
                        "message": "Login successful",
                        "role": data["users"][username]["role"],
                        "anonymous_id": data["users"][username]["anonymous_id"]
                    })
                else:
                    response = create_message("ERROR", {"error": "Invalid username or password"})
                    
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
                    
                    # Check if the user's token for this round has been used
                    user_token = data["round_tokens"][current_round][username]
                    if user_token in data["used_tokens"]:
                        response = create_message("ERROR", {"error": "You have already used your token for this round"})
                    else:
                        response = create_message("SUCCESS", {
                            "token": user_token,
                            "round": data["current_round"]
                        })
                else:
                    response = create_message("ERROR", {"error": "User not found"})
                    
            elif message_type == MESSAGE_TYPES["SEND_MESSAGE"]:
                sender = message_data.get("sender")
                recipient = message_data.get("recipient")
                content = message_data.get("content")
                round_token = message_data.get("token")
                current_round = str(data["current_round"])
                
                # Check if sender is admin (admins can't send messages)
                if data["users"][sender]["role"] == "admin":
                    response = create_message("ERROR", {"error": "Admins cannot send messages"})
                # Check if sender is banned
                elif data["users"][sender].get("is_banned", False):
                    response = create_message("ERROR", {"error": "You are banned from sending messages"})
                # Check if token is valid
                elif round_token not in data["round_tokens"][current_round].values():
                    response = create_message("ERROR", {"error": "Invalid token"})
                # Check if token is banned
                elif round_token in data["banned_tokens"]:
                    response = create_message("ERROR", {"error": "This token has been banned"})
                # Check if token has already been used
                elif round_token in data["used_tokens"]:
                    response = create_message("ERROR", {"error": "This token has already been used"})
                elif all([sender, recipient, content, round_token]):
                    if recipient not in data["messages"]:
                        data["messages"][recipient] = []
                    
                    message_id = f"msg{int(time.time())}"
                    data["messages"][recipient].append({
                        "id": message_id,
                        "sender": sender,
                        "sender_anonymous_id": data["users"][sender]["anonymous_id"],
                        "content": content,
                        "timestamp": datetime.now().isoformat(),
                        "is_flagged": False,
                        "round": data["current_round"],
                        "round_token": round_token
                    })
                    # Mark token as used
                    data["used_tokens"].append(round_token)
                    save_data(data)
                    response = create_message("SUCCESS", {"message": "Message sent"})
                else:
                    response = create_message("ERROR", {"error": "Missing required fields"})
                    
            elif message_type == MESSAGE_TYPES["REQUEST_MESSAGES"]:
                username = message_data.get("username")
                round_number = message_data.get("round_number")
                if username and round_number:
                    messages = data["messages"].get(username, [])
                    response = create_message("SUCCESS", {
                        "messages": messages,
                        "round_number": round_number
                    })
                else:
                    response = create_message("ERROR", {"error": "Missing username"})
                    
            elif message_type == MESSAGE_TYPES["FLAG_MESSAGE"]:
                username = message_data.get("username")
                message_id = message_data.get("message_id")
                reason = message_data.get("reason")
                
                if all([username, message_id, reason]):
                    # Find the message in all users' messages
                    for user_messages in data["messages"].values():
                        for msg in user_messages:
                            if msg["id"] == message_id:
                                msg["is_flagged"] = True
                                data["flagged_messages"][message_id] = {
                                    "flagged_by": username,
                                    "reason": reason,
                                    "timestamp": datetime.now().isoformat(),
                                    "sender_anonymous_id": msg["sender_anonymous_id"]
                                }
                                save_data(data)
                                response = create_message("SUCCESS", {"message": "Message flagged"})
                                break
                        else:
                            continue
                        break
                    else:
                        response = create_message("ERROR", {"error": "Message not found"})
                else:
                    response = create_message("ERROR", {"error": "Missing required fields"})
                    
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
                
                if username and data["users"][username]["role"] == "admin":
                    data["current_round"] += 1
                    data["round_tokens"][str(data["current_round"])] = {}
                    # Clear all messages for the new round
                    data["messages"] = {}
                    # Clear flagged messages as well
                    data["flagged_messages"] = {}
                    # Clear used tokens for the new round
                    data["used_tokens"] = []
                    save_data(data)
                    response = create_message("SUCCESS", {
                        "message": f"Round {data['current_round']} started",
                        "round": data["current_round"]
                    })
                else:
                    response = create_message("ERROR", {"error": "Unauthorized"})
                    
            elif message_type == MESSAGE_TYPES["MODERATOR_FLAG"]:
                message_id = message_data.get("message_id")
                reason = message_data.get("reason")
                moderator = message_data.get("moderator")
                
                if all([message_id, reason, moderator]):
                    # Find the message in all inboxes
                    message_found = False
                    for username, inbox in inboxes.items():
                        for round_num, messages in inbox.items():
                            for msg in messages:
                                if msg["id"] == message_id:
                                    # Add to moderator's queue
                                    flagged_message = {
                                        "message_id": message_id,
                                        "reason": reason,
                                        "content": msg["content"],
                                        "sender": username,
                                        "round": round_num,
                                        "timestamp": str(uuid.uuid1())
                                    }
                                    add_to_moderator_queue(moderator, flagged_message)
                                    message_found = True
                                    break
                            if message_found:
                                break
                        if message_found:
                            break
                    
                    if message_found:
                        response = create_message("SUCCESS", {
                            "status": "Message added to moderator queue",
                            "moderator": moderator
                        })
                    else:
                        response = create_message("ERROR", {"error": "Message not found"})
                else:
                    response = create_message("ERROR", {"error": "Missing required fields"})

            elif message_type == MESSAGE_TYPES["MODERATOR_QUEUE"]:
                moderator = message_data.get("moderator")
                if moderator:
                    queue = get_moderator_queue(moderator)
                    response = create_message("SUCCESS", {
                        "messages": queue,
                        "moderator": moderator
                    })
                else:
                    response = create_message("ERROR", {"error": "Missing moderator name"})

            elif message_type == MESSAGE_TYPES["REVIEW_MESSAGE"]:
                message_id = message_data.get("message_id")
                action = message_data.get("action")
                moderator = message_data.get("moderator")
                
                if all([message_id, action, moderator]) and action in ["approve", "reject", "ignore", "ban_sender"]:
                    # Find the message in all users' messages
                    message_found = False
                    sender = None
                    for username, messages in data["messages"].items():
                        for msg in messages:
                            if msg["id"] == message_id:
                                message_found = True
                                sender = msg["sender"]
                                if action == "ban_sender":
                                    # Ban the sender
                                    data["users"][sender]["is_banned"] = True
                                    save_data(data)
                                break
                        if message_found:
                            break
                    
                    if message_found:
                        # Remove message from moderator's queue
                        queue = get_moderator_queue(moderator)
                        for i, msg in enumerate(queue):
                            if msg["message_id"] == message_id:
                                queue.pop(i)
                                break
                        
                        if action == "ignore":
                            response = create_message("SUCCESS", {
                                "status": f"Message marked as fine by {moderator}",
                                "message_id": message_id
                            })
                        elif action == "ban_sender":
                            response = create_message("SUCCESS", {
                                "status": f"Message sender banned by {moderator}",
                                "message_id": message_id,
                                "banned_user": sender
                            })
                        else:
                            response = create_message("SUCCESS", {
                                "status": f"Message {action}ed by {moderator}",
                                "message_id": message_id
                            })
                    else:
                        response = create_message("ERROR", {"error": "Message not found"})
                else:
                    response = create_message("ERROR", {"error": "Invalid review action or missing fields"})

            else:
                print(f"Unknown message type: {message_type}")
                response = create_message("ERROR", {"error": f"Unknown message type: {message_type}"})
            
            # Send response
            print(f"\n=== Server Response ===")
            print(f"Sending: {response}")
            print("=====================\n")
            conn.send(response.encode())
            
        except Exception as e:
            print(f"\n=== Error ===")
            print(f"Error handling client {address}: {str(e)}")
            print("=============\n")
            break
    
    print(f"Connection from {address} closed")
    conn.close()

def main():
    host = socket.gethostname()
    port = 5001
    
    server_socket = socket.socket()
    server_socket.bind((host, port))
    server_socket.listen(5)
    
    print(f"Server started on {host}:{port}")
    print("\n=== Available Users ===")
    for username, user_data in data["users"].items():
        print(f"Username: {username}, Password: {user_data['password']}, Role: {user_data['role']}")
    print("=====================\n")
    
    while True:
        conn, address = server_socket.accept()
        client_thread = threading.Thread(target=handle_client, args=(conn, address))
        client_thread.start()

if __name__ == "__main__":
    main()

    