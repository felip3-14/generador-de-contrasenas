import json
import os
from datetime import datetime
from typing import List, Optional
from .models import PasswordEntry
from .encryption import LocalEncryption

class PasswordStorage:
    def __init__(self, storage_file: str = "passwords.json"):
        self.storage_file = storage_file
        self.encryption: Optional[LocalEncryption] = None
        self.entries: List[PasswordEntry] = []
        
    def initialize(self, master_password: str) -> None:
        """Initialize storage with master password"""
        if not os.path.exists(self.storage_file):
            self.encryption = LocalEncryption(master_password)
            self._save_empty_storage()
        else:
            with open(self.storage_file, 'r') as f:
                data = json.load(f)
                salt = bytes.fromhex(data['salt'])
                self.encryption = LocalEncryption(master_password, salt)
                self._load_entries(data['encrypted_data']['platforms'])
                
    def _save_empty_storage(self) -> None:
        """Create initial empty storage file"""
        initial_data = {
            "version": "1.0",
            "salt": self.encryption.get_salt().hex(),
            "encrypted_data": {"platforms": []}
        }
        self._save_data(initial_data)
        
    def _save_data(self, data: dict) -> None:
        """Save data to storage file"""
        with open(self.storage_file, 'w') as f:
            json.dump(data, f, indent=4)
            
    def _load_entries(self, encrypted_platforms: list) -> None:
        """Load and decrypt password entries"""
        self.entries = []
        for entry in encrypted_platforms:
            decrypted_password = self.encryption.decrypt(bytes.fromhex(entry['encrypted_password']))
            self.entries.append(PasswordEntry(
                platform=entry['platform'],
                username=entry['username'],
                password=decrypted_password,
                date_created=datetime.fromisoformat(entry['date_created']),
                last_modified=datetime.fromisoformat(entry['last_modified'])
            ))
            
    def add_password(self, platform: str, username: str, password: str) -> None:
        """Add a new password entry"""
        entry = PasswordEntry(
            platform=platform,
            username=username,
            password=password,
            date_created=datetime.now()
        )
        self.entries.append(entry)
        self._save_entries()
        
    def _save_entries(self) -> None:
        """Save all entries to storage"""
        encrypted_platforms = []
        for entry in self.entries:
            encrypted_password = self.encryption.encrypt(entry.password)
            encrypted_platforms.append({
                'platform': entry.platform,
                'username': entry.username,
                'encrypted_password': encrypted_password.hex(),
                'date_created': entry.date_created.isoformat(),
                'last_modified': entry.last_modified.isoformat()
            })
            
        data = {
            "version": "1.0",
            "salt": self.encryption.get_salt().hex(),
            "encrypted_data": {"platforms": encrypted_platforms}
        }
        self._save_data(data)
        
    def get_passwords(self) -> List[PasswordEntry]:
        """Get all password entries"""
        return self.entries
        
    def search_passwords(self, query: str) -> List[PasswordEntry]:
        """Search passwords by platform or username"""
        query = query.lower()
        return [
            entry for entry in self.entries
            if query in entry.platform.lower() or query in entry.username.lower()
        ] 