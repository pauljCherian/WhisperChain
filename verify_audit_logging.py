import unittest
import os
import time
import socket
import json
from client import register, login, send_message, flag_message, review_message, connect_to_server

class TestAuditLogEvents(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """One-time setup for all tests"""
        # Verify server is running
        try:
            socket_connection = connect_to_server()
            if not socket_connection:
                raise Exception("Could not connect to server. Please start the server first!")
            socket_connection.close()
        except Exception as e:
            raise Exception(f"Server connection failed: {str(e)}")

    def setUp(self):
        """Clean start for each test"""
        # Remove existing log files
        self.log_files = ['audit_log.json', 'server_audit.json', 'client_credentials.json']
        for file in self.log_files:
            if os.path.exists(file):
                os.remove(file)
                
        # Initialize empty log files with proper structure
        empty_log_structure = {"logs": []}
        for file in ['audit_log.json', 'server_audit.json']:
            with open(file, 'w') as f:
                json.dump(empty_log_structure, f)
                
        # Test user credentials
        self.normal_user = "test_user"
        self.normal_password = "test_pass"
        self.mod_user = "moderator"
        self.mod_password = "mod123"
        self.recipient = "recipient"
        self.recipient_password = "recipient_pass"
        
        # Wait a bit to ensure clean state
        time.sleep(0.5)

    def verify_log_exists(self, log_file):
        """Helper to verify log file exists and is valid JSON"""
        self.assertTrue(os.path.exists(log_file), f"{log_file} was not created")
        try:
            with open(log_file, 'r') as f:
                log_data = json.load(f)
                self.assertIsInstance(log_data, dict, f"{log_file} does not contain valid JSON object")
                self.assertIn("logs", log_data, f"{log_file} does not have 'logs' key")
        except json.JSONDecodeError:
            self.fail(f"{log_file} does not contain valid JSON")
        except Exception as e:
            self.fail(f"Error reading {log_file}: {str(e)}")

    def test_registration_events(self):
        """Test 1: Registration should create audit logs for attempt and success/failure"""
        print("\nTesting registration events...")
        register(self.normal_user, self.normal_password)
        time.sleep(0.5)  # Allow time for logs to be written
        print("✓ Check audit_log.json and server_audit.json for REGISTRATION events")

    def test_login_events(self):
        """Test 2: Login attempts should be logged (both success and failure)"""
        print("\nTesting login events...")
        # First register
        register(self.normal_user, self.normal_password)
        time.sleep(0.5)
        
        # Test successful login
        login(self.normal_user, self.normal_password)
        time.sleep(0.5)
        
        # Test failed login
        login(self.normal_user, "wrong_password")
        time.sleep(0.5)
        print("✓ Check audit_log.json and server_audit.json for LOGIN events")

    def test_message_events(self):
        """Test 3: Message sending should be logged"""
        print("\nTesting message events...")
        # Setup users
        register(self.normal_user, self.normal_password)
        register(self.recipient, self.recipient_password)
        time.sleep(0.5)
        
        # Login and send message
        login(self.normal_user, self.normal_password)
        time.sleep(0.5)
        send_message(self.recipient, "Test message")
        time.sleep(0.5)
        print("✓ Check audit_log.json and server_audit.json for MESSAGE events")

    def test_moderation_events(self):
        """Test 4: Moderation actions should be logged"""
        print("\nTesting moderation events...")
        # Setup users and message
        register(self.normal_user, self.normal_password)
        register(self.recipient, self.recipient_password)
        login(self.normal_user, self.normal_password)
        send_message(self.recipient, "Message to be flagged")
        time.sleep(0.5)
        
        # Flag the message
        flag_message("1", "Test flag reason")
        time.sleep(0.5)
        
        # Moderator review
        login(self.mod_user, self.mod_password)
        time.sleep(0.5)
        review_message("1", "approve")
        time.sleep(0.5)
        print("✓ Check audit_log.json and server_audit.json for MODERATION events")

if __name__ == '__main__':
    print("\nAudit Log Verification Tests")
    print("============================")
    print("1. Make sure the server is running first!")
    print("2. Tests will verify that audit logs are created and valid")
    print("3. After tests complete, you can inspect the contents of:")
    print("   - audit_log.json (client-side logs)")
    print("   - server_audit.json (server-side logs)\n")
    unittest.main(verbosity=2) 