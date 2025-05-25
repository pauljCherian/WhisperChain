from client import register, login, send_message, flag_message, review_message
import time

def generate_sample_logs():
    """Generate sample audit logs demonstrating various scenarios"""
    print("Generating sample audit logs...")
    
    # 1. User Registration (success and failure)
    print("\n1. Testing Registration Events:")
    register("alice", "password123")  # Successful registration
    register("alice", "password123")  # Failed registration (duplicate user)
    time.sleep(0.5)
    
    # 2. Login Attempts (success and failure)
    print("\n2. Testing Login Events:")
    login("alice", "password123")     # Successful login
    login("alice", "wrongpassword")   # Failed login
    login("nonexistent", "pass123")   # Failed login (user doesn't exist)
    time.sleep(0.5)
    
    # 3. Message Operations
    print("\n3. Testing Message Events:")
    register("bob", "password456")    # Create recipient
    time.sleep(0.5)
    login("alice", "password123")     # Login as sender
    time.sleep(0.5)
    send_message("bob", "Hello Bob!") # Normal message
    send_message("bob", "Secret message with sensitive content") # Message to be flagged
    time.sleep(0.5)
    
    # 4. Moderation Actions
    print("\n4. Testing Moderation Events:")
    login("bob", "password456")       # Login as recipient
    time.sleep(0.5)
    flag_message("2", "Contains sensitive information")  # Flag a message
    time.sleep(0.5)
    login("moderator", "mod123")      # Login as moderator
    time.sleep(0.5)
    review_message("2", "approve")    # Review flagged message
    time.sleep(0.5)
    
    print("\nSample logs generated!")
    print("\nYou can now examine:")
    print("1. audit_log.json - Client-side audit logs")
    print("2. server_audit.json - Server-side audit logs")
    print("\nThe logs demonstrate:")
    print("- User registration (success/failure)")
    print("- Login attempts (success/failure)")
    print("- Message operations (send/receive)")
    print("- Moderation actions (flag/review)")
    print("- Role-based actions (user/moderator)")
    print("- Session tracking")
    print("- Timestamps and metadata")
    print("- Digital signatures (if implemented)")

if __name__ == "__main__":
    print("Make sure the server is running before starting!")
    input("Press Enter to continue...")
    generate_sample_logs() 