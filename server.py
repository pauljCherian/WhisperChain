import socket
import threading

import hashlib 
import os 
import json
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

# stores encrypted message in a json file related for the recipient 
def store_message(recipient, ciphertext, round_number): 
    # json file entries: {username, {round_number: [list of messages]}}
    with open('messages.json', 'r') as file:
        data = json.load(file)
    
    # check the recipient exists
    if recipient not in data:
        data[recipient] = {}

    # check the round exists
    if round_number not in data[recipient]:
        data[recipient][round_number] = []

    # append the new message
    data[recipient][round_number].append(ciphertext)

    # write updated data back
    with open('messages.json', 'w') as f:
        json.dump(data)

# connecting clients 
def handle_client(conn, address):
    print(f"new connection from the client {address}")
    while True:
        try:
            # receive data from client, max 
            data = conn.recv(1024).decode()
            if not data:
                # if data is not received break
                break
            print(f"from {address}: {data}")
            # Echo back to client
            conn.send(data.encode())
        except:
            break
    
    print(f"connection from the client {address} closed")
    conn.close()

def main():
    print("server is running")
    # get the hostname
    host = socket.gethostname()
    port = 5001  #pick a port above 1000 so not conflicting 
    
    # Create a socket object
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

    