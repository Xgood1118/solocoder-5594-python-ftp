import json
import os
import threading
import time
from dataclasses import dataclass, field, asdict
from typing import Dict, Optional

import bcrypt

import config
from audit_logger import AuditLogger


@dataclass
class User:
    username: str
    password_hash: str
    home_dir: str
    quota_bytes: int = 0
    permissions: str = "r"
    failed_logins: int = 0
    locked_until: float = 0.0

    def has_permission(self, perm_flag: str) -> bool:
        return perm_flag in self.permissions

    def is_locked(self) -> bool:
        if self.locked_until <= 0:
            return False
        return time.time() < self.locked_until

    def record_failed_login(self):
        self.failed_logins += 1
        if self.failed_logins >= config.MAX_LOGIN_ATTEMPTS:
            self.locked_until = time.time() + config.LOCKOUT_DURATION

    def record_successful_login(self):
        self.failed_logins = 0
        self.locked_until = 0.0

    def to_dict(self) -> dict:
        return {
            "username": self.username,
            "password_hash": self.password_hash,
            "home_dir": self.home_dir,
            "quota_bytes": self.quota_bytes,
            "permissions": self.permissions,
            "failed_logins": self.failed_logins,
            "locked_until": self.locked_until,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "User":
        return cls(
            username=data["username"],
            password_hash=data["password_hash"],
            home_dir=data["home_dir"],
            quota_bytes=data.get("quota_bytes", 0),
            permissions=data.get("permissions", "r"),
            failed_logins=data.get("failed_logins", 0),
            locked_until=data.get("locked_until", 0.0),
        )


class UserManager:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self._users: Dict[str, User] = {}
        self._file_lock = threading.Lock()
        self._audit = AuditLogger()
        self._load()

    def _load(self):
        os.makedirs(os.path.dirname(config.USERS_DB), exist_ok=True)
        if not os.path.exists(config.USERS_DB):
            return
        with self._file_lock:
            with open(config.USERS_DB, "r", encoding="utf-8") as f:
                data = json.load(f)
        for user_data in data:
            user = User.from_dict(user_data)
            self._users[user.username] = user

    def _save(self):
        with self._file_lock:
            data = [u.to_dict() for u in self._users.values()]
            with open(config.USERS_DB, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)

    def add_user(self, username: str, password: str, permissions: str = "r",
                 quota_bytes: int = 0) -> Optional[User]:
        if username in self._users:
            return None
        password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        home_dir = os.path.join(config.USERS_DIR, username)
        os.makedirs(home_dir, exist_ok=True)
        user = User(
            username=username,
            password_hash=password_hash,
            home_dir=home_dir,
            quota_bytes=quota_bytes,
            permissions=permissions,
        )
        self._users[username] = user
        self._save()
        return user

    def verify_password(self, username: str, password: str) -> bool:
        user = self._users.get(username)
        if user is None:
            return False
        return bcrypt.checkpw(password.encode("utf-8"), user.password_hash.encode("utf-8"))

    def get_user(self, username: str) -> Optional[User]:
        return self._users.get(username)

    def check_login(self, username: str, password: str, client_ip: str = "0.0.0.0") -> tuple:
        user = self._users.get(username)
        if user is None:
            self._audit.log(username, client_ip, "LOGIN", "", "denied", "530")
            return False, "530 Authentication failed.", None

        if user.is_locked():
            self._audit.log(username, client_ip, "LOGIN", "", "denied", "530")
            return False, "530 Account locked due to too many failed attempts.", None

        if not self.verify_password(username, password):
            user.record_failed_login()
            self._save()
            self._audit.log(username, client_ip, "LOGIN", "", "denied", "530")
            if user.is_locked():
                return False, "530 Account locked due to too many failed attempts.", None
            return False, "530 Authentication failed.", None

        user.record_successful_login()
        self._save()
        self._audit.log(username, client_ip, "LOGIN", "", "success")
        return True, "230 Login successful.", user

    def set_quota(self, username: str, quota_bytes: int) -> bool:
        user = self._users.get(username)
        if user is None:
            return False
        user.quota_bytes = quota_bytes
        self._save()
        return True

    def set_permissions(self, username: str, permissions: str) -> bool:
        user = self._users.get(username)
        if user is None:
            return False
        valid = set(permissions).issubset({config.PERM_READ, config.PERM_WRITE, config.PERM_DELETE, config.PERM_ADMIN})
        if not valid:
            return False
        user.permissions = permissions
        self._save()
        return True

    def get_usage(self, username: str) -> int:
        user = self._users.get(username)
        if user is None:
            return 0
        return self._calculate_dir_size(user.home_dir)

    @staticmethod
    def _calculate_dir_size(path: str) -> int:
        total = 0
        for dirpath, dirnames, filenames in os.walk(path):
            for f in filenames:
                fp = os.path.join(dirpath, f)
                try:
                    total += os.path.getsize(fp)
                except OSError:
                    pass
        return total

    def check_quota(self, username: str, additional_bytes: int = 0) -> bool:
        user = self._users.get(username)
        if user is None:
            return False
        if user.quota_bytes <= 0:
            return True
        current = self.get_usage(username)
        return (current + additional_bytes) <= user.quota_bytes

    def list_users(self):
        return list(self._users.values())

    def remove_user(self, username: str) -> bool:
        if username not in self._users:
            return False
        del self._users[username]
        self._save()
        return True
