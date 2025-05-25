import json
import time
import fcntl
import os
from datetime import datetime
from typing import Optional, Dict, Any

class AuditLogger:
    def __init__(self, log_file: str = "audit_log.json"):
        self.log_file = log_file
        self._ensure_log_file_exists()
    
    def _ensure_log_file_exists(self):
        """Ensure the log file exists and is properly initialized"""
        try:
            if not os.path.exists(self.log_file):
                # Create new file with empty logs array
                with open(self.log_file, 'w') as f:
                    fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                    f.write('')
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        except Exception as e:
            print(f"Error ensuring log file exists: {str(e)}")
    
    def _append_log(self, log_entry: dict):
        """Append a single log entry to file with file locking"""
        try:
            with open(self.log_file, 'a') as f:
                # Get exclusive lock
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                try:
                    # Write the log entry
                    f.write(json.dumps(log_entry) + '\n')
                    # Ensure it's written to disk
                    f.flush()
                    os.fsync(f.fileno())
                finally:
                    # Always release the lock
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        except Exception as e:
            print(f"Error appending log: {str(e)}")
    
    def _read_logs(self) -> dict:
        """Read logs with shared lock and validate format"""
        logs = []
        try:
            with open(self.log_file, 'r') as f:
                # Get shared lock for reading
                fcntl.flock(f.fileno(), fcntl.LOCK_SH)
                try:
                    for line in f:
                        if line.strip():  # Skip empty lines
                            try:
                                log_entry = json.loads(line)
                                # Validate required fields
                                if all(key in log_entry for key in ["timestamp", "action", "user_role"]):
                                    logs.append(log_entry)
                            except json.JSONDecodeError:
                                print(f"Warning: Invalid log entry found: {line}")
                finally:
                    # Always release the lock
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        except Exception as e:
            print(f"Error reading logs: {str(e)}")
        return {"logs": logs}
    
    def log_event(self, 
                  action: str,
                  user_role: str,
                  round_token: Optional[str] = None,
                  round_number: Optional[int] = None,
                  event_details: Optional[Dict[str, Any]] = None) -> None:
        """Log an event with the specified fields"""
        try:
            timestamp = datetime.now().isoformat()
            
            log_entry = {
                "timestamp": timestamp,
                "action": action,
                "user_role": user_role,
                "round_token": round_token,
                "round_number": round_number,
                "event_details": event_details or {}
            }
            
            # Append the entry
            self._append_log(log_entry)
        except Exception as e:
            print(f"Error logging event: {str(e)}")
    
    def get_round_activity(self, round_number: int) -> list:
        """Get all activity for a specific round"""
        logs = self._read_logs()
        return [log for log in logs["logs"] if log["round_number"] == round_number] 