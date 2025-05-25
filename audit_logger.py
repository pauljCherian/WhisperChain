import json
import time
from datetime import datetime
from typing import Optional, Dict, Any
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import base64

class AuditLogger:
    def __init__(self, log_file: str = "audit_log.json"):
        self.log_file = log_file
        # Generate or load signing key
        try:
            with open('audit_signing_key.pem', 'rb') as f:
                self.signing_key = serialization.load_pem_private_key(f.read(), password=None)
        except FileNotFoundError:
            self.signing_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            # Save the key
            with open('audit_signing_key.pem', 'wb') as f:
                f.write(self.signing_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
        self._ensure_log_file_exists()
    
    def _ensure_log_file_exists(self):
        """Ensure the log file exists"""
        try:
            with open(self.log_file, 'r') as f:
                # Try to read the file
                pass
        except FileNotFoundError:
            # Create new file with empty line
            with open(self.log_file, 'w') as f:
                f.write('')
    
    def _sign_entry(self, entry: dict) -> str:
        """Sign a log entry and return the signature"""
        # Sort keys to ensure consistent ordering for signing
        entry_bytes = json.dumps(entry, sort_keys=True).encode()
        signature = self.signing_key.sign(
            entry_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode()

    def _append_log(self, log_entry: dict):
        """Append a single log entry to file"""
        # Add signature to entry
        log_entry['signature'] = self._sign_entry(log_entry)
        
        # Append to file
        with open(self.log_file, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
    
    def _read_logs(self) -> dict:
        """Read logs and return in backward-compatible format"""
        logs = []
        try:
            with open(self.log_file, 'r') as f:
                for line in f:
                    if line.strip():  # Skip empty lines
                        logs.append(json.loads(line))
        except (FileNotFoundError, json.JSONDecodeError):
            # Return empty logs if file doesn't exist or is invalid
            pass
        return {"logs": logs}
    
    def log_event(self, 
                  action: str,
                  username: str,
                  role: str,
                  session_id: str,
                  token_id: Optional[str] = None,
                  round_number: Optional[int] = None,
                  additional_data: Optional[Dict[str, Any]] = None) -> None:
        """Log a security event with comprehensive metadata"""
        timestamp = datetime.now().isoformat()
        unix_timestamp = int(time.time())
        
        log_entry = {
            "timestamp": timestamp,
            "unix_timestamp": unix_timestamp,
            "action": action,
            "username": username,
            "role": role,
            "session_id": session_id,
            "token_id": token_id,
            "round_number": round_number,
            "ip_address": None,  # To be filled by the server
            "success": True,  # Default to True, can be updated for failed actions
            "metadata": additional_data or {}
        }
        
        # Append the signed entry
        self._append_log(log_entry)
    
    def log_security_event(self,
                          event_type: str,
                          username: str,
                          success: bool,
                          details: str,
                          session_id: str,
                          role: str) -> None:
        """Log a security-specific event (login attempts, permission changes, etc.)"""
        self.log_event(
            action=f"SECURITY_{event_type}",
            username=username,
            role=role,
            session_id=session_id,
            additional_data={
                "success": success,
                "details": details,
                "event_type": event_type
            }
        )
    
    def get_user_activity(self, username: str, start_time: Optional[int] = None) -> list:
        """Get all activity for a specific user"""
        logs = self._read_logs()
        
        if start_time is None:
            return [log for log in logs["logs"] if log["username"] == username]
        else:
            return [
                log for log in logs["logs"]
                if log["username"] == username and log["unix_timestamp"] >= start_time
            ]
    
    def get_security_events(self, event_type: Optional[str] = None) -> list:
        """Get all security events, optionally filtered by type"""
        logs = self._read_logs()
        
        if event_type is None:
            return [log for log in logs["logs"] if log["action"].startswith("SECURITY_")]
        else:
            return [
                log for log in logs["logs"]
                if log["action"] == f"SECURITY_{event_type}"
            ]
    
    def get_round_activity(self, round_number: int) -> list:
        """Get all activity for a specific round"""
        logs = self._read_logs()
        return [log for log in logs["logs"] if log["round_number"] == round_number] 