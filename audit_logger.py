import json
import time
from datetime import datetime
from typing import Optional, Dict, Any

class AuditLogger:
    def __init__(self, log_file: str = "audit_log.json"):
        self.log_file = log_file
        self._ensure_log_file_exists()
    
    def _ensure_log_file_exists(self):
        """Ensure the log file exists and has valid JSON structure"""
        try:
            with open(self.log_file, 'r') as f:
                json.load(f)
        except FileNotFoundError:
            with open(self.log_file, 'w') as f:
                json.dump({"logs": []}, f)
        except json.JSONDecodeError:
            with open(self.log_file, 'w') as f:
                json.dump({"logs": []}, f)
    
    def _read_logs(self) -> dict:
        """Read the current logs from file"""
        with open(self.log_file, 'r') as f:
            return json.load(f)
    
    def _write_logs(self, logs: dict):
        """Write logs to file"""
        with open(self.log_file, 'w') as f:
            json.dump(logs, f, indent=4)
    
    def log_event(self, 
                  action: str,
                  username: str,
                  role: str,
                  session_id: str,
                  token_id: Optional[str] = None,
                  round_number: Optional[int] = None,
                  additional_data: Optional[Dict[str, Any]] = None) -> None:
        """
        Log a security event with comprehensive metadata
        
        Args:
            action: The action being performed (e.g., "login", "send_message", etc.)
            username: The username performing the action
            role: The role of the user (admin, moderator, user)
            session_id: Current session ID
            token_id: Optional round token ID
            round_number: Optional round number
            additional_data: Optional dictionary of additional metadata
        """
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
        
        # Read current logs
        logs = self._read_logs()
        
        # Append new entry
        logs["logs"].append(log_entry)
        
        # Write back to file
        self._write_logs(logs)
    
    def log_security_event(self,
                          event_type: str,
                          username: str,
                          success: bool,
                          details: str,
                          session_id: str,
                          role: str) -> None:
        """
        Log a security-specific event (login attempts, permission changes, etc.)
        """
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