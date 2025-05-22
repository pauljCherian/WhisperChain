import socket
import threading
import json
import time
from datetime import datetime
from message_types import create_message, parse_message

# Load data from JSON file
def load_data():
    try:
        with open('data.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print("data.json not found, creating new data structure")
        return {
            "users": {},
            "messages": {},
            "flagged_messages": {}
        }

# Save data to JSON file
def save_data(data):
    with open('data.json', 'w') as f:
        json.dump(data, f, indent=4)

# Global data
data = load_data()

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
            if message_type == "LOGIN":
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
                    response = create_message("SUCCESS", {
                        "message": "Login successful",
                        "role": data["users"][username]["role"]
                    })
                else:
                    response = create_message("ERROR", {"error": "Invalid username or password"})
                    
            elif message_type == "SEND_MESSAGE":
                sender = message_data.get("sender")
                recipient = message_data.get("recipient")
                content = message_data.get("content")
                
                # Check if sender is admin (admins can't send messages)
                if data["users"][sender]["role"] == "admin":
                    response = create_message("ERROR", {"error": "Admins cannot send messages"})
                # Check if sender is banned
                elif data["users"][sender].get("is_banned", False):
                    response = create_message("ERROR", {"error": "You are banned from sending messages"})
                elif all([sender, recipient, content]):
                    if recipient not in data["messages"]:
                        data["messages"][recipient] = []
                    
                    message_id = f"msg{int(time.time())}"
                    data["messages"][recipient].append({
                        "id": message_id,
                        "sender": sender,
                        "content": content,
                        "timestamp": datetime.now().isoformat(),
                        "is_flagged": False
                    })
                    save_data(data)
                    response = create_message("SUCCESS", {"message": "Message sent"})
                else:
                    response = create_message("ERROR", {"error": "Missing required fields"})
                    
            elif message_type == "REQUEST_MESSAGES":
                username = message_data.get("username")
                
                if username:
                    user_messages = data["messages"].get(username, [])
                    response = create_message("SUCCESS", {
                        "messages": user_messages
                    })
                else:
                    response = create_message("ERROR", {"error": "Missing username"})
                    
            elif message_type == "FLAG_MESSAGE":
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
                                    "timestamp": datetime.now().isoformat()
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
                    
            elif message_type == "GET_FLAGGED_MESSAGES":
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
                    
            elif message_type == "BAN_USER":
                moderator = message_data.get("moderator")
                target_user = message_data.get("target_user")
                
                if (moderator and target_user and 
                    data["users"][moderator]["role"] == "moderator" and
                    data["users"][target_user]["role"] == "user"):
                    data["users"][target_user]["is_banned"] = True
                    save_data(data)
                    response = create_message("SUCCESS", {"message": f"User {target_user} has been banned"})
                else:
                    response = create_message("ERROR", {"error": "Unauthorized or invalid user"})
                    
            elif message_type == "MAKE_MODERATOR":
                admin = message_data.get("admin")
                target_user = message_data.get("target_user")
                
                if (admin and target_user and 
                    data["users"][admin]["role"] == "admin" and
                    data["users"][target_user]["role"] == "user"):
                    data["users"][target_user]["role"] = "moderator"
                    save_data(data)
                    response = create_message("SUCCESS", {"message": f"User {target_user} is now a moderator"})
                else:
                    response = create_message("ERROR", {"error": "Unauthorized or invalid user"})
                    
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

    