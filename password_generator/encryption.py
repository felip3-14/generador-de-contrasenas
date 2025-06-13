import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class LocalEncryption:
    def __init__(self, master_password: str, salt: bytes = None):
        self.master_password = master_password
        self.salt = salt or os.urandom(16)
        self.key = self._derive_key()
        
    def _derive_key(self) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(self.master_password.encode()))
        
    def encrypt(self, data: str) -> bytes:
        f = Fernet(self.key)
        return f.encrypt(data.encode())
        
    def decrypt(self, encrypted_data: bytes) -> str:
        f = Fernet(self.key)
        return f.decrypt(encrypted_data).decode()
        
    def get_salt(self) -> bytes:
        return self.salt 