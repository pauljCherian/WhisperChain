import json

# Message type constants
LOGIN = "LOGIN"
SEND_MESSAGE = "SEND_MESSAGE"
REQUEST_MESSAGES = "REQUEST_MESSAGES"
FLAG_MESSAGE = "FLAG_MESSAGE"
GET_FLAGGED_MESSAGES = "GET_FLAGGED_MESSAGES"
BAN_USER = "BAN_USER"
MAKE_MODERATOR = "MAKE_MODERATOR"
SUCCESS = "SUCCESS"
ERROR = "ERROR"

MESSAGE_TYPES = {
    "LOGIN": LOGIN,
    "SEND_MESSAGE": SEND_MESSAGE,
    "REQUEST_MESSAGES": REQUEST_MESSAGES,
    "FLAG_MESSAGE": FLAG_MESSAGE,
    "GET_FLAGGED_MESSAGES": GET_FLAGGED_MESSAGES,
    "BAN_USER": BAN_USER,
    "MAKE_MODERATOR": MAKE_MODERATOR,
    "SUCCESS": SUCCESS,
    "ERROR": ERROR
}

def create_message(message_type, data):
    """
    Create a simple JSON message with type and data
    """
    return json.dumps({
        "type": message_type,
        "data": data
    })

def parse_message(message_str):
    """
    Parse a JSON message string into its type and data
    """
    try:
        message = json.loads(message_str)
        return message.get("type"), message.get("data", {})
    except json.JSONDecodeError:
        return None, None

# Message format examples:
# SEND_MESSAGE: {'sender': 'username', 'recipient': 'username', 'content': 'encrypted_message'}
# FLAG_MESSAGE: {'message_id': 'id', 'reason': 'reason_for_flag'}
# REVIEW_MESSAGE: {'message_id': 'id', 'action': 'approve/reject'}
# REQUEST_MESSAGES: {'username': 'username', 'round_number': 'round_number'} 