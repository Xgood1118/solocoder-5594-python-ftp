import os
import re

import config
from audit_logger import AuditLogger
from user_manager import UserManager


class CustomAuthorizer:

    def __init__(self):
        self._user_manager = UserManager()
        self._audit = AuditLogger()
        self._msg_login = "Login successful."
        self._msg_quit = "Goodbye."

    @staticmethod
    def sanitize_filename(filename: str) -> str:
        filename = re.sub(r"\.\./|\.\.\\", "", filename)
        filename = re.sub(r"[/\\]+", os.sep, filename)
        return filename.strip(os.sep)

    @staticmethod
    def validate_path(home_dir: str, target_path: str) -> bool:
        real_home = os.path.realpath(home_dir)
        real_target = os.path.realpath(target_path)
        return real_target.startswith(real_home + os.sep) or real_target == real_home

    def resolve_virtual_path(self, username: str, virtual_path: str) -> str:
        user = self._user_manager.get_user(username)
        if user is None:
            return ""
        virtual_path = self.sanitize_filename(virtual_path)
        physical = os.path.join(user.home_dir, virtual_path)
        return os.path.normpath(physical)

    def check_path_safety(self, username: str, virtual_path: str, client_ip: str = "0.0.0.0") -> tuple:
        user = self._user_manager.get_user(username)
        if user is None:
            return False, ""
        virtual_path = self.sanitize_filename(virtual_path)
        physical = os.path.normpath(os.path.join(user.home_dir, virtual_path))
        if not self.validate_path(user.home_dir, physical):
            self._audit.log(
                username, client_ip, "PATH_TRAVERSAL", virtual_path, "denied", "550"
            )
            return False, physical
        return True, physical

    def validate_authentication(self, username: str, password: str, handler):
        from pyftpdlib.authorizers import AuthenticationFailed as PyFTPAuthFailed
        client_ip = handler.remote_ip if handler else "0.0.0.0"
        success, msg, user = self._user_manager.check_login(username, password, client_ip)
        if not success:
            raise PyFTPAuthFailed(msg)

    def get_home_dir(self, username):
        user = self._user_manager.get_user(username)
        if user is None:
            from pyftpdlib.authorizers import AuthenticationFailed
            raise AuthenticationFailed("No such user")
        return user.home_dir

    def has_user(self, username):
        return self._user_manager.get_user(username) is not None

    def has_perm(self, username, perm, path=None):
        user = self._user_manager.get_user(username)
        if user is None:
            return False
        perm_flag = self._map_perm_to_flag(perm)
        if perm_flag is None:
            return False
        return user.has_permission(perm_flag)

    @staticmethod
    def _map_perm_to_flag(perm):
        for flag, commands in config.PERM_MAP.items():
            if perm in commands:
                return flag
        return None

    def get_perms(self, username):
        user = self._user_manager.get_user(username)
        if user is None:
            return ""
        mapped = ""
        for flag in user.permissions:
            if flag == config.PERM_READ:
                mapped += "elr"
            elif flag == config.PERM_WRITE:
                mapped += "adfmw"
            elif flag == config.PERM_DELETE:
                mapped += "f"
        return mapped

    def get_msg_login(self, username):
        return self._msg_login

    def get_msg_quit(self, username):
        return self._msg_quit

    def add_user(self, username, password, homedir, perm="elr", msg_login="Login successful.", msg_quit="Goodbye."):
        pass

    def add_anonymous(self, homedir, **kwargs):
        pass

    def remove_user(self, username):
        pass

    def impersonate_user(self, username, password):
        pass

    def terminate_user(self, username):
        pass
