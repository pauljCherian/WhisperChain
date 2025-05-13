from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64

def generate_fernet_key(master_password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=1_200_000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return key

def encrypt(key, plaintext):
    encrypted_text = Fernet(key).encrypt(plaintext.encode()).decode()
    return encrypted_text

def decrypt(key, encrypted_text):
    decrypted_text = Fernet(key).decrypt(encrypted_text.encode()).decode()
    return decrypted_text