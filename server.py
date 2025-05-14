import socket
import threading

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

    