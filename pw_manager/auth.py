import os
from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def create_master_pw(mpw):
    salt = os.urandom(17)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=1_200_000,
    )
    key = kdf.derive(mpw.encode())
    return salt, key

## returns True if input password is same as master password, False if not
def validate_password(mpw, salt, input_pw):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=1_200_000,
    )
    try: ## if verification works, pw is correct
        kdf.verify(input_pw, mpw)
        print("You have successfully logged in!")
        return True
    
    except InvalidKey: ## verification doesn't work, pw is incorrect
        print("Given master password is wrong :(")
        return False