from dataclasses import dataclass
from datetime import datetime

@dataclass
class PasswordEntry:
    platform: str
    username: str
    password: str
    date_created: datetime
    last_modified: datetime = None

    def __post_init__(self):
        if self.last_modified is None:
            self.last_modified = self.date_created 