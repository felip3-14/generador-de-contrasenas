import json
import os
import bcrypt

SETTINGS_FILE = "settings.json"
DEFAULT_PUBLIC_KEY = "iLoveCod3"
DEFAULT_PRIVATE_KEY = "GITHUBM4!N"

class SecurityManager:
    def __init__(self):
        self.settings_path = SETTINGS_FILE
        self._load_or_init_settings()

    def _hash(self, value):
        # Generar un salt aleatorio y hashear la contraseña
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(value.encode(), salt).decode()

    def _verify_hash(self, value, hashed):
        # Verificar si la contraseña coincide con el hash
        return bcrypt.checkpw(value.encode(), hashed.encode())

    def _load_or_init_settings(self):
        if not os.path.exists(self.settings_path):
            self.settings = {
                "public_key": self._hash(DEFAULT_PUBLIC_KEY),
                "private_key": self._hash(DEFAULT_PRIVATE_KEY)
            }
            self._save_settings()
        else:
            with open(self.settings_path, 'r') as f:
                self.settings = json.load(f)

    def _save_settings(self):
        with open(self.settings_path, 'w') as f:
            json.dump(self.settings, f, indent=4)

    def validate_public_key(self, key):
        return self._verify_hash(key, self.settings["public_key"])

    def validate_private_key(self, key):
        return self._verify_hash(key, self.settings["private_key"])

    def change_keys(self, old_public, old_private, new_public, new_private):
        if not self.validate_public_key(old_public):
            return False, "Clave pública actual incorrecta."
        if not self.validate_private_key(old_private):
            return False, "Clave privada actual incorrecta."
        self.settings["public_key"] = self._hash(new_public)
        self.settings["private_key"] = self._hash(new_private)
        self._save_settings()
        return True, "Claves actualizadas correctamente." 