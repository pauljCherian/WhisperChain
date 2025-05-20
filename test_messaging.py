import socket
import json
import time
from message_types import MESSAGE_TYPES, create_message, parse_message

def connect_to_server():
    host = socket.gethostname()
    port = 5001
    client_socket = socket.socket()
    client_socket.connect((host, port))
    return client_socket

def send_test_message(sender, recipient, content, client_socket):
    message_data = {
        'sender': sender,
        'recipient': recipient,
        'content': content  # In real implementation, this would be encrypted
    }
    message_str = create_message(MESSAGE_TYPES['SEND_MESSAGE'], message_data)
    client_socket.send(message_str.encode())
    response = client_socket.recv(1024).decode()
    return parse_message(response)

def request_messages(username, round_number, client_socket):
    message_data = {
        'username': username,
        'round_number': round_number
    }
    message_str = create_message(MESSAGE_TYPES['REQUEST_MESSAGES'], message_data)
    client_socket.send(message_str.encode())
    response = client_socket.recv(1024).decode()
    return parse_message(response)

def test_messaging_system():
    print("Starting messaging system test...")
    
    # Test 1: Send message between two users
    print("\nTest 1: Sending message between users")
    client1 = connect_to_server()
    client2 = connect_to_server()
    
    # Send message from user1 to user2
    response_type, response_data = send_test_message(
        "user1", "user2", "Hello from user1!", client1
    )
    print(f"Send message response: {response_type} - {response_data}")
    
    # Request messages for user2
    response_type, response_data = request_messages("user2", 1, client2)
    print(f"User2's messages: {response_data}")
    
    # Test 2: Send message in new round
    print("\nTest 2: Sending message in new round")
    response_type, response_data = send_test_message(
        "user2", "user1", "Hello from user2 in round 2!", client2
    )
    print(f"Send message response: {response_type} - {response_data}")
    
    # Request messages for user1 in round 2
    response_type, response_data = request_messages("user1", 2, client1)
    print(f"User1's messages in round 2: {response_data}")
    
    # Test 3: Flag a message
    print("\nTest 3: Flagging a message")
    if response_data and 'messages' in response_data and response_data['messages']:
        message_id = response_data['messages'][0]['id']
        flag_data = {
            'message_id': message_id,
            'reason': 'Test flag'
        }
        message_str = create_message(MESSAGE_TYPES['FLAG_MESSAGE'], flag_data)
        client1.send(message_str.encode())
        response = client1.recv(1024).decode()
        response_type, response_data = parse_message(response)
        print(f"Flag message response: {response_type} - {response_data}")
    
    # Clean up
    client1.close()
    client2.close()
    print("\nTest completed!")

if __name__ == "__main__":
    test_messaging_system() 