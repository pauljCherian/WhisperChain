import socket
import threading
import json
import hashlib 
import os 
import base64



from crypto_utils import *

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
    
# Get the public key for a registered user
def get_public_key(username): 
    public_key = None
    # json file entries: {username, public_key}
    with open('public_keys.json', 'r') as file:
        data = json.load(file)
    
    # looks up in the json file and retrieves 
    public_key = data.get(username)

    return public_key

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
                return str({'error': 'username not provided'})
            
            public_key = get_public_key(username)
            if public_key:
                return str({'type': 'public_key', 'key': public_key})
            else:
                return str({'error': 'public key not found'})
        else:
            return str({'error': 'invalid request type'})
        
        # ADD MORE REQUEST TYPES HERE. SHOULD BE ABLE TO HANDLE ALL OTHER REQUESTS FROM CLIENT
    except:
        return str({'error': 'invalid request format'})

# saves public key to the public_key.json file 
def store_public_key(public_key): 
    pass 

# connecting clients 
def handle_client(conn, address):
    print(f"new connection from client {address}")
    while True:
        try:
            # receive data from client
            data = conn.recv(1024).decode()
            if not data:
                break
                
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
    print("server is running")
    # get the hostname
    host = socket.gethostname()
    port = 5001  #pick a port above 1000 so not conflicting 
    
    # create a socket object
    server_socket = socket.socket()
    server_socket.bind((host, port)) 
    server_socket.listen(8) # allow max 8 connections
    
    print(f"server running on hist {host}: and port {port}")
    
    while True:
        # accept new connection
        conn, address = server_socket.accept()
        # create a new thread to accept the client
        client_thread = threading.Thread(target=handle_client, args=(conn, address))
        client_thread.start()

if __name__ == "__main__":
    main()

    