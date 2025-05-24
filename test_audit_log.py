import json
import time
import socket
from client import login, register, send_message, flag_message, appoint_moderator, ban_token, start_new_round
from audit_logger import AuditLogger

def check_server_running():
    """Check if the server is running and reachable"""
    print("Checking if server is running...")
    try:
        # Try to connect to the server
        test_socket = socket.socket()
        host = socket.gethostname()
        print(f"Attempting to connect to {host}:5001")
        test_socket.connect((host, 5001))
        test_socket.close()
        print("Successfully connected to server")
        return True
    except Exception as e:
        print(f"Failed to connect to server: {str(e)}")
        return False

def print_logs(audit_logger, description):
    """Helper function to print logs in a readable format"""
    print(f"\n=== {description} ===")
    logs = audit_logger._read_logs()
    for log in logs["logs"]:
        print("\nLog Entry:")
        print(f"  Timestamp: {log['timestamp']}")
        print(f"  Action: {log['action']}")
        print(f"  Username: {log['username']}")
        print(f"  Role: {log['role']}")
        print(f"  Session ID: {log['session_id']}")
        if log['token_id']:
            print(f"  Token ID: {log['token_id']}")
        if log['metadata']:
            print(f"  Metadata: {log['metadata']}")
        print("---")

def run_single_test(test_name, test_func, *args):
    """Run a single test with proper error handling"""
    print(f"\nRunning test: {test_name}")
    try:
        result = test_func(*args)
        print(f"Test completed: {test_name}")
        return result
    except Exception as e:
        print(f"Test failed: {test_name}")
        print(f"Error: {str(e)}")
        return None

def run_tests():
    """Run a series of tests to verify audit logging"""
    print("\nStarting test sequence...")
    
    # Check if server is running
    if not check_server_running():
        print("\nERROR: Server is not running!")
        print("Please start the server first by running 'python server.py' in a separate terminal")
        print("Then run this test script again")
        return

    # Initialize audit logger
    print("\nInitializing audit logger...")
    audit_logger = AuditLogger()
    
    print("\nStarting audit log tests...")
    
    try:
        # Test 1: Register new users
        print("\nTest 1: Registering users...")
        run_single_test("Register user 1", register, "testuser1", "password123")
        run_single_test("Register user 2", register, "testuser2", "password123")
        print_logs(audit_logger, "Registration Logs")
        
        # Test 2: Failed login attempt
        print("\nTest 2: Testing failed login...")
        run_single_test("Failed login", login, "testuser1", "wrongpassword")
        print_logs(audit_logger, "Failed Login Logs")
        
        # Test 3: Successful login
        print("\nTest 3: Testing successful login...")
        run_single_test("Successful login", login, "testuser1", "password123")
        print_logs(audit_logger, "Successful Login Logs")
        
        # Test 4: Send message
        print("\nTest 4: Sending message...")
        run_single_test("Send message", send_message, "testuser2", "Hello, this is a test message!")
        print_logs(audit_logger, "Message Sending Logs")
        
        # Test 5: Unauthorized moderator action
        print("\nTest 5: Testing unauthorized moderator action...")
        run_single_test("Unauthorized flag", flag_message, "msg123", "test reason")
        print_logs(audit_logger, "Unauthorized Action Logs")
        
        # Test 6: Admin login and moderator appointment
        print("\nTest 6: Testing admin actions...")
        run_single_test("Admin login", login, "admin", "admin123")
        run_single_test("Appoint moderator", appoint_moderator, "testuser1")
        print_logs(audit_logger, "Admin Action Logs")
        
        # Test 7: Moderator actions
        print("\nTest 7: Testing moderator actions...")
        run_single_test("Moderator login", login, "testuser1", "password123")
        run_single_test("Ban token", ban_token, "test_token")
        print_logs(audit_logger, "Moderator Action Logs")
        
        # Test 8: Round management
        print("\nTest 8: Testing round management...")
        run_single_test("Admin login", login, "admin", "admin123")
        run_single_test("Start new round", start_new_round)
        print_logs(audit_logger, "Round Management Logs")
        
        # Print summary statistics
        logs = audit_logger._read_logs()
        total_logs = len(logs["logs"])
        security_events = len([log for log in logs["logs"] if log["action"].startswith("SECURITY_")])
        
        print("\n=== Test Summary ===")
        print(f"Total log entries: {total_logs}")
        print(f"Security events: {security_events}")
        print("==================")
        
    except Exception as e:
        print(f"\nERROR: Test failed with error: {str(e)}")
        print("Make sure the server is still running and try again")

if __name__ == "__main__":
    print("Starting audit log test script...")
    run_tests() 