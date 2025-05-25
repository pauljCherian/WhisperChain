# WhisperChain
## Team Members: Isabelle, Paul, Leyla, Rhianna

## Overview

WhisperChain is a secure, role-based messaging platform that allows users to communicate anonymously, with support for moderation and message flagging. The system is composed of several core components, each responsible for a different aspect of the application's functionality.

### File Descriptions

#### `client.py`
This file implements the client-side application. It provides the user interface for connecting to the server, registering or logging in, sending and receiving messages, and interacting with features such as flagging messages or viewing moderator actions (depending on the role - user, moderator, admin). The client communicates with the server using a defined set of message types and handles responses accordingly. The role-based access controls are enforced here. 

#### `server.py`
This file contains the server-side logic. It manages user authentication, message routing, role assignments (such as admin, moderator, and user), and enforces security and moderation policies. The server processes incoming requests from clients, updates the `data.json` file.

#### `message_types.py`
This file defines the set of message types and constants used for communication between the client and server. By standardizing message formats and types, it ensures consistent and reliable protocol exchanges, making it easier to extend or modify the system's capabilities in the future.

## Setup Instructions

1. **Clone the Repository**
   ```
   git clone https://github.com/pauljCherian/WhisperChain.git
   cd WhisperChain
   ```

2. **Install Python 3**
   - Ensure you have Python 3.7 or higher installed. You can check your version with:
     ```
     python3 --version
     ```
   - If not installed, download it from [python.org](https://www.python.org/downloads/).


3. **Install Required Packages**
   - A`requirements.txt` is provided in the repo:
     ```
     pip install -r requirements.txt
     ```

5. **Run the Server**
   ```
   python3 server.py
   ```

6. **Run the Client (in a separate terminal)**
   ```
   python3 client.py
   ```

7. **Register or Log In**
   - Follow the prompts in the client application to register a new user or log in with existing credentials.

8. **Start Messaging!**
   - Use the client interface to send messages, flag inappropriate content, or (if you have the appropriate role) moderate conversations.

**Note:**  
- The application uses a `data.json` file for persistent storage. Make sure this file is present in the project directory.
- For local testing, both server and client can be run on the same machine. For remote access, ensure the server's port is accessible and update the hostname in `client.py` if necessary.
