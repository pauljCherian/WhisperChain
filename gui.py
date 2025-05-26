import tkinter as tk
from tkinter import simpledialog, messagebox, scrolledtext
from client import *
import socket
import base64
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization

class ConnectionManager:
    def __init__(self):
        self.socket = None
        
    def connect(self):
        try:
            if self.socket is None:
                self.socket = connect_to_server()
                if self.socket is None:
                    raise ConnectionError("Failed to connect to server")
            return True
        except Exception as e:
            print(f"Connection error: {str(e)}")
            return False
            
    def disconnect(self):
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
            self.socket = None

class MessagingApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure Messaging Client (Shh!)")
        self.geometry("500x600")
        
        # Set colors and font
        self.configure(bg='#E6E6FA')  # Light lavender background
        self.text_color = '#4B0082'  # Dark purple text
        self.font = ('Georgia', 16)  # Larger Georgia font
        
        self.current_user = None
        self.user_role = None
        self.conn_manager = ConnectionManager()
        self.private_key = None
        self.current_round = 1
        self.current_round_token = None
        
        # Create output area with a border and custom scrollbar
        output_frame = tk.Frame(self, bg='#E6E6FA', highlightbackground=self.text_color, highlightthickness=3)
        output_frame.pack(pady=10, padx=40, fill='x', expand=False)

        self.output_area = tk.Text(
            output_frame,
            height=15,
            width=60,
            state='disabled',
            bg='#E6E6FA',
            fg=self.text_color,
            font=self.font,
            bd=0,
            highlightthickness=0,
            insertbackground=self.text_color,
            selectbackground='#D1C4E9',
            selectforeground=self.text_color
        )
        scrollbar = tk.Scrollbar(output_frame, command=self.output_area.yview, bg='#E6E6FA', troughcolor='#E6E6FA')
        self.output_area['yscrollcommand'] = scrollbar.set

        self.output_area.pack(side=tk.LEFT, fill='both', expand=True)
        scrollbar.pack(side=tk.RIGHT, fill='y')

        self.main_frame = tk.Frame(self, bg='#E6E6FA')
        self.main_frame.pack(padx=40, fill='x', expand=False)  # Centered, equal padding
        
        # Initialize connection and show welcome screen
        if self.ensure_connection():
            self.show_welcome_screen()
        else:
            self.quit()

    def ensure_connection(self):
        """Ensure we have a valid socket connection"""
        if not self.conn_manager.connect():
            messagebox.showerror("Connection Error", "Failed to connect to server. Please ensure the server is running.")
            return False
        return True

    def create_account_encryption(self, username, password):
        """Create encryption keys and hash password for new account"""
        # Hash the password
        salt_b64, hashed_password = hash_password(password)
        
        # Create a new key pair for the user
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = self.private_key.public_key()

        # Convert the key pair to base64 for storage
        private_key_b64 = base64.b64encode(self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )).decode()

        public_key_b64 = base64.b64encode(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )).decode()
        
        # Store the credentials in client_credentials.json
        credentials = {
            'username': username,
            'private_key': private_key_b64,
            'salt': salt_b64,
        }
        write_json('client_credentials.json', credentials)

        return public_key_b64, hashed_password

    def send_request_with_retry(self, request_type, data=None):
        """Send a request with automatic reconnection if needed"""
        if data is None:
            data = {}
            
        try:
            # Ensure we have a valid connection
            if not self.ensure_connection():
                return False, {"error": "Could not establish connection to server"}
            
            # Create and send message
            message = create_message(request_type, data)
            print(f"Sending: {message}")
            
            # Try to send the message, reconnect if needed
            try:
                self.conn_manager.socket.send(message.encode())
            except (BrokenPipeError, ConnectionResetError):
                print("Connection lost. Attempting to reconnect...")
                if not self.ensure_connection():
                    return False, {"error": "Could not reconnect to server"}
                self.conn_manager.socket.send(message.encode())
            
            # Set a timeout for receiving the response
            self.conn_manager.socket.settimeout(10)  # 10 second timeout
            
            try:
                # Get response
                response = self.conn_manager.socket.recv(1024).decode()
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
            if self.conn_manager.socket is not None:
                self.conn_manager.socket.settimeout(None)

    def clear_main_frame(self):
        for widget in self.main_frame.winfo_children():
            widget.destroy()

    def show_welcome_screen(self):
        self.clear_main_frame()
        tk.Label(self.main_frame, text="Welcome to the Messaging Client!", 
                bg='#E6E6FA', fg=self.text_color, font=self.font).pack(pady=10)
        tk.Button(self.main_frame, text="Login", width=15, command=self.show_login_screen,
                 bg='#E6E6FA', fg=self.text_color, font=self.font).pack(pady=5)
        tk.Button(self.main_frame, text="Register", width=15, command=self.show_register_screen,
                 bg='#E6E6FA', fg=self.text_color, font=self.font).pack(pady=5)
        tk.Button(self.main_frame, text="Exit", width=15, command=self.quit,
                 bg='#E6E6FA', fg=self.text_color, font=self.font).pack(pady=5)

    def show_login_screen(self):
        self.clear_main_frame()
        tk.Label(self.main_frame, text="Login", bg='#E6E6FA', fg=self.text_color, font=self.font).pack(pady=10)
        tk.Label(self.main_frame, text="Username:", bg='#E6E6FA', fg=self.text_color, font=self.font).pack()
        username_entry = tk.Entry(self.main_frame, font=self.font)
        username_entry.pack()
        username_entry.focus_set()
        tk.Label(self.main_frame, text="Password:", bg='#E6E6FA', fg=self.text_color, font=self.font).pack()
        password_entry = tk.Entry(self.main_frame, show="*", font=self.font)
        password_entry.pack()
        def attempt_login():
            if not self.ensure_connection():
                return
            username = username_entry.get()
            password = password_entry.get()
            
            # Handle special users (admin/moderator) differently
            if username in ["admin", "moderator"]:
                # Don't hash password for admin/moderator
                success, response = self.send_request_with_retry("LOGIN", {
                    "username": username,
                    "password": password  # Send plain text password
                })
            else:
                # Get stored salt and hash the password for regular users
                try:
                    salt_b64 = read_json('client_credentials.json').get('salt')
                    if not salt_b64:
                        messagebox.showerror("Login Error", "No credentials found. Please register first.")
                        return
                        
                    salt = base64.b64decode(salt_b64.encode())
                    kdf = PBKDF2HMAC(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=salt,
                        iterations=100000,
                    )
                    hashed_password = base64.b64encode(kdf.derive(password.encode())).decode()
                    
                    success, response = self.send_request_with_retry("LOGIN", {
                        "username": username,
                        "password": hashed_password
                    })
                except Exception as e:
                    messagebox.showerror("Login Error", f"Error during login: {str(e)}")
                    return
            
            if success:
                self.current_user = username
                self.user_role = response.get("role")
                self.display_output(f"Logged in as {username} ({self.user_role})")
                self.show_role_menu()
            else:
                messagebox.showerror("Login Failed", response.get("error", "Invalid username or password."))
        tk.Button(self.main_frame, text="Login", command=attempt_login,
                 bg='#E6E6FA', fg=self.text_color, font=self.font).pack(pady=5)
        tk.Button(self.main_frame, text="Back", command=self.show_welcome_screen,
                 bg='#E6E6FA', fg=self.text_color, font=self.font).pack(pady=5)

    def show_register_screen(self):
        self.clear_main_frame()
        tk.Label(self.main_frame, text="Register", bg='#E6E6FA', fg=self.text_color, font=self.font).pack(pady=10)
        tk.Label(self.main_frame, text="Username:", bg='#E6E6FA', fg=self.text_color, font=self.font).pack()
        username_entry = tk.Entry(self.main_frame, font=self.font)
        username_entry.pack()
        username_entry.focus_set()
        tk.Label(self.main_frame, text="Password:", bg='#E6E6FA', fg=self.text_color, font=self.font).pack()
        password_entry = tk.Entry(self.main_frame, show="*", font=self.font)
        password_entry.pack()
        def attempt_register():
            if not self.ensure_connection():
                return
            username = username_entry.get()
            password = password_entry.get()
            
            try:
                # Create encryption keys and hash password
                public_key_b64, hashed_password = self.create_account_encryption(username, password)
                
                success, response = self.send_request_with_retry("REGISTER", {
                    "username": username,
                    "password": hashed_password,
                    "public_key": public_key_b64
                })
                
                if success:
                    # Store the token for the current round
                    self.current_round_token = response.get("token")
                    self.current_round = response.get("round", 1)
                    
                    # Log successful registration
                    audit_logger.log_event(
                        action="REGISTRATION",
                        user_role="unregistered",
                        round_number=self.current_round,
                        event_details={"success": True, "username": username}
                    )
                    
                    self.display_output(f"Registration successful! Got round token for round {self.current_round}")
                    self.show_login_screen()
                else:
                    error_msg = response.get('error', 'Unknown error')
                    # Log failed registration
                    audit_logger.log_event(
                        action="REGISTRATION",
                        user_role="unregistered",
                        round_number=self.current_round,
                        event_details={"success": False, "username": username, "error": error_msg}
                    )
                    messagebox.showerror("Registration Failed", f"Registration failed: {error_msg}")
            except Exception as e:
                # Log registration error
                audit_logger.log_event(
                    action="REGISTRATION",
                    user_role="unregistered",
                    round_number=self.current_round,
                    event_details={"success": False, "username": username, "error": str(e)}
                )
                messagebox.showerror("Registration Error", f"Error during registration: {str(e)}")
        tk.Button(self.main_frame, text="Register", command=attempt_register,
                 bg='#E6E6FA', fg=self.text_color, font=self.font).pack(pady=5)
        tk.Button(self.main_frame, text="Back", command=self.show_welcome_screen,
                 bg='#E6E6FA', fg=self.text_color, font=self.font).pack(pady=5)

    def show_role_menu(self):
        self.clear_main_frame()
        if self.user_role == "admin":
            self.show_admin_menu()
        elif self.user_role == "moderator":
            self.show_moderator_menu()
        else:
            self.show_user_menu()

    def show_user_menu(self):
        self.clear_main_frame()
        tk.Label(self.main_frame, text=f"User Menu ({self.current_user})", 
                bg='#E6E6FA', fg=self.text_color, font=self.font).pack(pady=10)
        tk.Button(self.main_frame, text="Send Message", width=20, command=self.show_send_message_screen,
                 bg='#E6E6FA', fg=self.text_color, font=self.font).pack(pady=5)
        tk.Button(self.main_frame, text="Read Messages", width=20, command=self.show_read_messages_screen,
                 bg='#E6E6FA', fg=self.text_color, font=self.font).pack(pady=5)
        tk.Button(self.main_frame, text="Flag Message", width=20, command=self.show_flag_message_screen,
                 bg='#E6E6FA', fg=self.text_color, font=self.font).pack(pady=5)
        tk.Button(self.main_frame, text="Logout", width=20, command=self.show_welcome_screen,
                 bg='#E6E6FA', fg=self.text_color, font=self.font).pack(pady=5)

    def show_send_message_screen(self):
        self.clear_main_frame()
        tk.Label(self.main_frame, text="Send Message", bg='#E6E6FA', fg=self.text_color, font=self.font).pack(pady=10)
        tk.Label(self.main_frame, text="Recipient:", bg='#E6E6FA', fg=self.text_color, font=self.font).pack()
        recipient_entry = tk.Entry(self.main_frame, font=self.font)
        recipient_entry.pack()
        recipient_entry.focus_set()
        tk.Label(self.main_frame, text="Message:", bg='#E6E6FA', fg=self.text_color, font=self.font).pack()
        message_entry = tk.Entry(self.main_frame, font=self.font)
        message_entry.pack()
        def send():
            if not self.ensure_connection():
                return
            recipient = recipient_entry.get()
            message = message_entry.get()
            
            try:
                # Get recipient's public key
                success, response = self.send_request_with_retry("GET_PUBLIC_KEY", {
                    "recipient": recipient
                })
                
                if not success:
                    self.display_output(f"Failed to get public key for {recipient}: {response.get('error', 'Unknown error')}")
                    return
                    
                public_key_b64 = response.get("public_key")
                if not public_key_b64:
                    self.display_output(f"No public key found for {recipient}")
                    return
                
                # Encrypt the message
                encrypted_message = encrypt_message(message, public_key_b64)
                
                # Get round token
                success, response = self.send_request_with_retry("GET_TOKEN", {
                    "username": self.current_user
                })
                
                if not success:
                    self.display_output(f"Failed to get round token: {response.get('error', 'Unknown error')}")
                    return
                    
                round_token = response.get("token")
                if not round_token:
                    self.display_output("No round token received")
                    return
                
                # Send the encrypted message
                success, response = self.send_request_with_retry("SEND_MESSAGE", {
                    "sender": self.current_user,
                    "recipient": recipient,
                    "content": encrypted_message,
                    "token": round_token
                })
                
                if success:
                    self.display_output(f"Message sent to {recipient}")
                else:
                    self.display_output(f"Failed to send message: {response.get('error', 'Unknown error')}")
            except Exception as e:
                self.display_output(f"Error sending message: {str(e)}")
            self.show_user_menu()
        tk.Button(self.main_frame, text="Send", command=send,
                 bg='#E6E6FA', fg=self.text_color, font=self.font).pack(pady=5)
        tk.Button(self.main_frame, text="Back", command=self.show_user_menu,
                 bg='#E6E6FA', fg=self.text_color, font=self.font).pack(pady=5)

    def show_read_messages_screen(self):
        self.clear_main_frame()
        tk.Label(self.main_frame, text="Read Messages", bg='#E6E6FA', fg=self.text_color, font=self.font).pack(pady=10)
        tk.Label(self.main_frame, text="Round Number:", bg='#E6E6FA', fg=self.text_color, font=self.font).pack()
        round_entry = tk.Entry(self.main_frame, font=self.font)
        round_entry.pack()
        round_entry.focus_set()
        def retrieve():
            if not self.ensure_connection():
                return
            round_number = round_entry.get()
            success, response = self.send_request_with_retry("REQUEST_MESSAGES", {
                "username": self.current_user,
                "round_number": round_number
            })
            if success:
                messages = response.get("messages", [])
                if messages:
                    for msg in messages:
                        try:
                            # Decrypt the message
                            decrypted_content = decrypt_message(msg.get("content"))
                            self.display_output(f"Message ID: {msg.get('message_id')}")
                            self.display_output(f"From Anonymous ID: {msg.get('sender_anonymous_id')}")
                            self.display_output(f"Content: {decrypted_content}")
                            self.display_output("-" * 50)  # Add separator between messages
                        except Exception as e:
                            self.display_output(f"Error decrypting message: {str(e)}")
                else:
                    self.display_output("No messages found for this round.")
            else:
                self.display_output(f"Failed to retrieve messages: {response.get('error', 'Unknown error')}")
            self.show_user_menu()
        tk.Button(self.main_frame, text="Read", command=retrieve,
                 bg='#E6E6FA', fg=self.text_color, font=self.font).pack(pady=5)
        tk.Button(self.main_frame, text="Back", command=self.show_user_menu,
                 bg='#E6E6FA', fg=self.text_color, font=self.font).pack(pady=5)

    def show_flag_message_screen(self):
        self.clear_main_frame()
        tk.Label(self.main_frame, text="Flag Message", bg='#E6E6FA', fg=self.text_color, font=self.font).pack(pady=10)
        tk.Label(self.main_frame, text="Message ID:", bg='#E6E6FA', fg=self.text_color, font=self.font).pack()
        msgid_entry = tk.Entry(self.main_frame, font=self.font)
        msgid_entry.pack()
        msgid_entry.focus_set()
        tk.Label(self.main_frame, text="Reason:", bg='#E6E6FA', fg=self.text_color, font=self.font).pack()
        reason_entry = tk.Entry(self.main_frame, font=self.font)
        reason_entry.pack()
        def flag():
            if not self.ensure_connection():
                return
            msgid = msgid_entry.get()
            reason = reason_entry.get()
            
            # First get the message and decrypt its content
            success, response = self.send_request_with_retry("GET_MESSAGE_BY_ID", {
                "message_id": msgid
            })
            
            if success:
                encrypted_content = response.get("content")
                content = decrypt_message(encrypted_content)
                
                # Now send the flag request with decrypted content
                success, response = self.send_request_with_retry("FLAG_MESSAGE", {
                    "username": self.current_user,
                    "message_id": msgid,
                    "reason": reason,
                    "content": content
                })
                
                if success:
                    self.display_output(f"Message {msgid} flagged successfully")
                else:
                    self.display_output(f"Failed to flag message: {response.get('error', 'Unknown error')}")
            else:
                self.display_output(f"Failed to get message: {response.get('error', 'Unknown error')}")
            self.show_user_menu()
        tk.Button(self.main_frame, text="Flag", command=flag,
                 bg='#E6E6FA', fg=self.text_color, font=self.font).pack(pady=5)
        tk.Button(self.main_frame, text="Back", command=self.show_user_menu,
                 bg='#E6E6FA', fg=self.text_color, font=self.font).pack(pady=5)

    def show_moderator_menu(self):
        self.clear_main_frame()
        if self.user_role != "moderator":
            self.display_output("Error: Only moderators can access this menu")
            self.show_welcome_screen()
            return
            
        tk.Label(self.main_frame, text=f"Moderator Menu ({self.current_user})", 
                bg='#E6E6FA', fg=self.text_color, font=self.font).pack(pady=10)
        tk.Button(self.main_frame, text="Review Flagged Messages", width=25, command=self.show_review_flagged_messages_screen,
                 bg='#E6E6FA', fg=self.text_color, font=self.font).pack(pady=5)
        tk.Button(self.main_frame, text="Block User", width=25, command=self.show_block_user_screen,
                 bg='#E6E6FA', fg=self.text_color, font=self.font).pack(pady=5)
        tk.Button(self.main_frame, text="View Audit Log", width=25, command=self.show_view_audit_log_screen,
                 bg='#E6E6FA', fg=self.text_color, font=self.font).pack(pady=5)
        tk.Button(self.main_frame, text="Logout", width=25, command=self.show_welcome_screen,
                 bg='#E6E6FA', fg=self.text_color, font=self.font).pack(pady=5)

    def show_admin_menu(self):
        self.clear_main_frame()
        if self.user_role != "admin":
            self.display_output("Error: Only admins can access this menu")
            self.show_welcome_screen()
            return
            
        tk.Label(self.main_frame, text=f"Admin Menu ({self.current_user})", 
                bg='#E6E6FA', fg=self.text_color, font=self.font).pack(pady=10)
        tk.Button(self.main_frame, text="Start New Round", width=20, command=self.show_start_new_round_screen,
                 bg='#E6E6FA', fg=self.text_color, font=self.font).pack(pady=5)
        tk.Button(self.main_frame, text="Appoint Moderator", width=20, command=self.show_appoint_moderator_screen,
                 bg='#E6E6FA', fg=self.text_color, font=self.font).pack(pady=5)
        tk.Button(self.main_frame, text="Logout", width=20, command=self.show_welcome_screen,
                 bg='#E6E6FA', fg=self.text_color, font=self.font).pack(pady=5)

    def show_review_flagged_messages_screen(self):
        self.clear_main_frame()
        tk.Label(self.main_frame, text="Review Flagged Messages", 
                bg='#E6E6FA', fg=self.text_color, font=self.font).pack(pady=10)
        
        # Check if user is a moderator
        if self.user_role != "moderator":
            self.display_output("Error: Only moderators can access the queue")
            tk.Button(self.main_frame, text="Back", command=self.show_moderator_menu,
                     bg='#E6E6FA', fg=self.text_color, font=self.font).pack(pady=5)
            return
            
        # Get flagged messages directly from server
        success, response = self.send_request_with_retry("GET_FLAGGED_MESSAGES", {
            "username": self.current_user
        })
        
        if success:
            flagged_messages = response.get("flagged_messages", {})
            if not flagged_messages:
                self.display_output("No flagged messages.")
            else:
                for message_id, msg in flagged_messages.items():
                    self.display_output(f"\nMessage ID: {message_id}")
                    self.display_output(f"From: {msg.get('sender_anonymous_id', 'Unknown')}")
                    self.display_output(f"Content: {msg.get('content', 'No content')}")
                    self.display_output(f"Reason: {msg.get('reason', 'No reason provided')}")
                    self.display_output(f"Flagged by: {msg.get('flagged_by', 'Unknown')}")
                    self.display_output(f"Timestamp: {msg.get('timestamp', 'Unknown')}")
                    self.display_output("-" * 50)
                
                tk.Label(self.main_frame, text="Message ID to review:", 
                        bg='#E6E6FA', fg=self.text_color, font=self.font).pack()
                msg_id_entry = tk.Entry(self.main_frame, font=self.font)
                msg_id_entry.pack()
                msg_id_entry.focus_set()
                
                # Create frame for action buttons
                action_frame = tk.Frame(self.main_frame, bg='#E6E6FA')
                action_frame.pack(pady=5)
                
                def ignore_message():
                    msg_id = msg_id_entry.get()
                    if msg_id:
                        success, response = self.send_request_with_retry("IGNORE_MESSAGE", {
                            "message_id": msg_id
                        })
                        if success:
                            self.display_output(f"Message {msg_id} ignored successfully")
                        else:
                            self.display_output(f"Failed to ignore message: {response.get('error', 'Unknown error')}")
                        self.show_moderator_menu()
                
                def block_sender():
                    msg_id = msg_id_entry.get()
                    if msg_id:
                        success, response = self.send_request_with_retry("BLOCK_MESSAGE", {
                            "message_id": msg_id,
                            "username": self.current_user
                        })
                        if success:
                            blocked_token = response.get("blocked_token")
                            self.display_output(f"Sender's token blocked successfully: {blocked_token}")
                        else:
                            self.display_output(f"Failed to block sender: {response.get('error', 'Unknown error')}")
                        self.show_moderator_menu()
                
                # Add action buttons
                tk.Button(action_frame, text="Ignore Message", command=ignore_message,
                         bg='#E6E6FA', fg=self.text_color, font=self.font).pack(side=tk.LEFT, padx=5)
                tk.Button(action_frame, text="Block Sender", command=block_sender,
                         bg='#E6E6FA', fg=self.text_color, font=self.font).pack(side=tk.LEFT, padx=5)
        else:
            self.display_output(f"Failed to get flagged messages: {response.get('error', 'Unknown error')}")
        tk.Button(self.main_frame, text="Back", command=self.show_moderator_menu,
                 bg='#E6E6FA', fg=self.text_color, font=self.font).pack(pady=5)

    def show_block_user_screen(self):
        self.clear_main_frame()
        if self.user_role != "moderator":
            self.display_output("Error: Only moderators can block users")
            self.show_moderator_menu()
            return
            
        tk.Label(self.main_frame, text="Block User", 
                bg='#E6E6FA', fg=self.text_color, font=self.font).pack(pady=10)
        tk.Label(self.main_frame, text="Username to block:", 
                bg='#E6E6FA', fg=self.text_color, font=self.font).pack()
        username_entry = tk.Entry(self.main_frame, font=self.font)
        username_entry.pack()
        username_entry.focus_set()
        def block():
            username = username_entry.get()
            if username:
                success, response = self.send_request_with_retry("BLOCK_USER", {
                    "username": username,
                    "moderator": self.current_user
                })
                if success:
                    self.display_output(f"Successfully blocked user {username}")
                else:
                    self.display_output(f"Failed to block user: {response.get('error', 'Unknown error')}")
            self.show_moderator_menu()
        tk.Button(self.main_frame, text="Block", command=block,
                 bg='#E6E6FA', fg=self.text_color, font=self.font).pack(pady=5)
        tk.Button(self.main_frame, text="Back", command=self.show_moderator_menu,
                 bg='#E6E6FA', fg=self.text_color, font=self.font).pack(pady=5)

    def show_view_audit_log_screen(self):
        self.clear_main_frame()
        if self.user_role != "moderator":
            self.display_output("Error: Only moderators can view audit logs")
            self.show_moderator_menu()
            return
            
        tk.Label(self.main_frame, text="Audit Log", 
                bg='#E6E6FA', fg=self.text_color, font=self.font).pack(pady=10)
        success, response = self.send_request_with_retry("GET_AUDIT_LOG", {
            "username": self.current_user
        })
        if success:
            log_entries = response.get("log", [])
            if not log_entries:
                self.display_output("No audit log entries found")
            else:
                for entry in log_entries:
                    self.display_output(f"\nTimestamp: {entry.get('timestamp')}")
                    self.display_output(f"Action: {entry.get('action')}")
                    self.display_output(f"User: {entry.get('username')}")
                    self.display_output(f"Role: {entry.get('role')}")
                    self.display_output(f"Round: {entry.get('round')}")
                    self.display_output("-" * 50)
        else:
            self.display_output(f"Failed to get audit log: {response.get('error', 'Unknown error')}")
        tk.Button(self.main_frame, text="Back", command=self.show_moderator_menu,
                 bg='#E6E6FA', fg=self.text_color, font=self.font).pack(pady=5)

    def show_start_new_round_screen(self):
        self.clear_main_frame()
        if self.user_role != "admin":
            self.display_output("Error: Only admins can start new rounds")
            self.show_admin_menu()
            return
            
        tk.Label(self.main_frame, text="Start New Round", 
                bg='#E6E6FA', fg=self.text_color, font=self.font).pack(pady=10)
        def start():
            success, response = self.send_request_with_retry("NEXT_ROUND", {
                "username": self.current_user
            })
            if success:
                self.display_output(f"Started new round {response.get('round')}")
            else:
                self.display_output(f"Failed to start new round: {response.get('error', 'Unknown error')}")
            self.show_admin_menu()
        tk.Button(self.main_frame, text="Start", command=start,
                 bg='#E6E6FA', fg=self.text_color, font=self.font).pack(pady=5)
        tk.Button(self.main_frame, text="Back", command=self.show_admin_menu,
                 bg='#E6E6FA', fg=self.text_color, font=self.font).pack(pady=5)

    def show_appoint_moderator_screen(self):
        self.clear_main_frame()
        if self.user_role != "admin":
            self.display_output("Error: Only admins can appoint moderators")
            self.show_admin_menu()
            return
            
        tk.Label(self.main_frame, text="Appoint Moderator", 
                bg='#E6E6FA', fg=self.text_color, font=self.font).pack(pady=10)
        tk.Label(self.main_frame, text="Username to appoint:", 
                bg='#E6E6FA', fg=self.text_color, font=self.font).pack()
        username_entry = tk.Entry(self.main_frame, font=self.font)
        username_entry.pack()
        username_entry.focus_set()
        def appoint():
            username = username_entry.get()
            if username:
                success, response = self.send_request_with_retry("APPOINT_MODERATOR", {
                    "admin": self.current_user,
                    "target_user": username
                })
                if success:
                    self.display_output(f"Successfully appointed {username} as moderator")
                else:
                    self.display_output(f"Failed to appoint moderator: {response.get('error', 'Unknown error')}")
            self.show_admin_menu()
        tk.Button(self.main_frame, text="Appoint", command=appoint,
                 bg='#E6E6FA', fg=self.text_color, font=self.font).pack(pady=5)
        tk.Button(self.main_frame, text="Back", command=self.show_admin_menu,
                 bg='#E6E6FA', fg=self.text_color, font=self.font).pack(pady=5)

    def display_output(self, text):
        self.output_area.config(state='normal')
        self.output_area.insert(tk.END, text + '\n')
        self.output_area.config(state='disabled')
        self.output_area.see(tk.END)

if __name__ == "__main__":
    app = MessagingApp()
    app.mainloop()
