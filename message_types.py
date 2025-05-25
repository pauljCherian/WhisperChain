import json

# Message type constants
LOGIN = "LOGIN"
REGISTER = "REGISTER"
SEND_MESSAGE = "SEND_MESSAGE"
REQUEST_MESSAGES = "REQUEST_MESSAGES"
FLAG_MESSAGE = "FLAG_MESSAGE"
GET_FLAGGED_MESSAGES = "GET_FLAGGED_MESSAGES"
BAN_USER = "BAN_USER"
MAKE_MODERATOR = "MAKE_MODERATOR"
GET_TOKEN = "GET_TOKEN"
BAN_TOKEN = "BAN_TOKEN"
NEXT_ROUND = "NEXT_ROUND"
APPOINT_MODERATOR = "APPOINT_MODERATOR"
SUCCESS = "SUCCESS"
ERROR = "ERROR"
IGNORE_MESSAGE = "IGNORE_MESSAGE"
BLOCK_MESSAGE = "BLOCK_MESSAGE"
MODERATOR_FLAG = "MODERATOR_FLAG"
MODERATOR_QUEUE = "MODERATOR_QUEUE"
GET_MODERATORS = "GET_MODERATORS"
BLOCK_USER = "BLOCK_USER"

MESSAGE_TYPES = {
    "LOGIN": LOGIN,
    "REGISTER": REGISTER,
    "SEND_MESSAGE": SEND_MESSAGE,
    "REQUEST_MESSAGES": REQUEST_MESSAGES,
    "FLAG_MESSAGE": FLAG_MESSAGE,
    "GET_FLAGGED_MESSAGES": GET_FLAGGED_MESSAGES,
    "BAN_USER": BAN_USER,
    "MAKE_MODERATOR": MAKE_MODERATOR,
    "GET_TOKEN": GET_TOKEN,
    "BAN_TOKEN": BAN_TOKEN,
    "NEXT_ROUND": NEXT_ROUND,
    "APPOINT_MODERATOR": APPOINT_MODERATOR,
    "MODERATOR_QUEUE": MODERATOR_QUEUE,
    "IGNORE_MESSAGE": IGNORE_MESSAGE,
    "BLOCK_MESSAGE": BLOCK_MESSAGE,
    "GET_MODERATORS": GET_MODERATORS,
    "BLOCK_USER": BLOCK_USER,
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
# IGNORE_MESSAGE: {'message_id': 'id'}
# REQUEST_MESSAGES: {'username': 'username', 'round_number': 'round_number'}
# MODERATOR_FLAG: {'message_id': 'id', 'reason': 'reason_for_flag', 'moderator': 'moderator_name'}
# MODERATOR_QUEUE: {'moderator': 'moderator_name', 'messages': [list of flagged messages]} 
# BLOCK_MESSAGE: {'message_id': 'id', 'username': 'username'}