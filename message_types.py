import json

# Message type constants
MESSAGE_TYPES = {
    'SEND_MESSAGE': 'SEND_MESSAGE',
    'FLAG_MESSAGE': 'FLAG_MESSAGE',
    'REVIEW_MESSAGE': 'REVIEW_MESSAGE',
    'REQUEST_MESSAGES': 'REQUEST_MESSAGES'
}

def create_message(message_type, data):
    """
    Create a formatted message with type and data
    """
    message = {
        'type': message_type,
        'data': data
    }
    return json.dumps(message)

def parse_message(message_str):
    """
    Parse a message string into its type and data
    """
    try:
        message = json.loads(message_str)
        return message.get('type'), message.get('data')
    except json.JSONDecodeError:
        return None, None

# Message format examples:
# SEND_MESSAGE: {'sender': 'username', 'recipient': 'username', 'content': 'encrypted_message'}
# FLAG_MESSAGE: {'message_id': 'id', 'reason': 'reason_for_flag'}
# REVIEW_MESSAGE: {'message_id': 'id', 'action': 'approve/reject'}
# REQUEST_MESSAGES: {'username': 'username', 'round_number': 'round_number'} 