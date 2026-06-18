import os
import shutil
import stat
import threading

from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

import config
from audit_logger import AuditLogger
from chunk_handler import ChunkHandler
from custom_authorizer import CustomAuthorizer
from user_manager import UserManager
from virtual_fs import VirtualFileSystem


class CustomFTPHandler(FTPHandler):
    authorizer = None

    def __init__(self, conn, server, ioloop=None):
        super().__init__(conn, server, ioloop=ioloop)
        self._audit = AuditLogger()
        self._chunk_handler = ChunkHandler()
        self._user_manager = UserManager()
        self._virtual_fs = VirtualFileSystem(self.authorizer)
        self._transfer_id = None
        self._resume_offset = 0

        self.proto_cmds["SITE QUOTA"] = {
            "perm": None, "auth": True, "arg": True,
            "help": "Syntax: SITE QUOTA <SP> username (query user quota).",
        }
        self.proto_cmds["SITE INFO"] = {
            "perm": None, "auth": True, "arg": None,
            "help": "Syntax: SITE INFO (show server info).",
        }
        self.proto_cmds["SITE CHPERM"] = {
            "perm": None, "auth": True, "arg": True,
            "help": "Syntax: SITE CHPERM <SP> username permissions (change user permissions).",
        }
        self.proto_cmds["SITE CHQUOTA"] = {
            "perm": None, "auth": True, "arg": True,
            "help": "Syntax: SITE CHQUOTA <SP> username quota (change user quota).",
        }

    def on_connect(self):
        self._audit.log("ANONYMOUS", self.remote_ip, "CONNECT")

    def on_disconnect(self):
        username = getattr(self, "username", None) or "ANONYMOUS"
        self._audit.log(username, self.remote_ip, "DISCONNECT")

    def on_login(self, username):
        user = self._user_manager.get_user(username)
        if user is None:
            self.close()
            return
        self.root = user.home_dir
        self.home = user.home_dir
        self.cwd = "/"
        self._audit.log(username, self.remote_ip, "LOGIN", "/", "success")

    def on_logout(self, username):
        if username:
            self._audit.log(username, self.remote_ip, "LOGOUT")

    def on_file_sent(self, file):
        username = getattr(self, "username", None) or "ANONYMOUS"
        self._audit.log(username, self.remote_ip, "RETR", file, "success")

    def on_file_received(self, file):
        username = getattr(self, "username", None) or "ANONYMOUS"
        if self._transfer_id:
            success = self._chunk_handler.merge_chunks(self._transfer_id)
            self._transfer_id = None
            if not success:
                self._audit.log(username, self.remote_ip, "STOR", file, "error", "552")
                return
        self._audit.log(username, self.remote_ip, "STOR", file, "success")

    def on_incomplete_file_sent(self, file):
        username = getattr(self, "username", None) or "ANONYMOUS"
        self._audit.log(username, self.remote_ip, "RETR", file, "incomplete")

    def on_incomplete_file_received(self, file):
        username = getattr(self, "username", None) or "ANONYMOUS"
        if self._transfer_id:
            self._chunk_handler.cancel_transfer(self._transfer_id)
            self._transfer_id = None
        self._audit.log(username, self.remote_ip, "STOR", file, "incomplete")

    def ftp_STOR(self, file, mode="w"):
        username = getattr(self, "username", None)
        if not username:
            self.respond("530 Not logged in.")
            return

        if not self.authorizer.has_perm(username, "STOR"):
            self._audit.log(username, self.remote_ip, "STOR", file, "denied", "550")
            self.respond("550 Permission denied.")
            return

        safe, physical = self.authorizer.check_path_safety(username, file, self.remote_ip)
        if not safe:
            self.respond("550 Path traversal detected. Connection closed.")
            self.close()
            return

        file_size = self._get_upload_size()
        if file_size and file_size > 0:
            if not self._user_manager.check_quota(username, file_size):
                self._audit.log(username, self.remote_ip, "STOR", file, "denied", "552")
                self.respond("552 Quota exceeded.")
                return

        disk_free = self._check_disk_space(physical)
        if disk_free is not None and disk_free < (file_size or 0):
            self._audit.log(username, self.remote_ip, "STOR", file, "denied", "452")
            self.respond("452 Insufficient disk space.")
            return

        if file_size and file_size > config.CHUNK_THRESHOLD:
            self._transfer_id = self._chunk_handler.create_transfer(
                username, physical, file_size
            )

        if self._resume_offset > 0 and os.path.exists(physical):
            mode = "a"

        try:
            return super().ftp_STOR(file, mode)
        except OSError as e:
            self._audit.log(username, self.remote_ip, "STOR", file, "error", str(e))
            self.respond("550 Upload failed.")
            return

    def ftp_APPE(self, file):
        username = getattr(self, "username", None)
        if not username:
            self.respond("530 Not logged in.")
            return

        if not self.authorizer.has_perm(username, "APPE"):
            self._audit.log(username, self.remote_ip, "APPE", file, "denied", "550")
            self.respond("550 Permission denied.")
            return

        safe, physical = self.authorizer.check_path_safety(username, file, self.remote_ip)
        if not safe:
            self.respond("550 Path traversal detected. Connection closed.")
            self.close()
            return

        return super().ftp_APPE(file)

    def ftp_RETR(self, file):
        username = getattr(self, "username", None)
        if not username:
            self.respond("530 Not logged in.")
            return

        if not self.authorizer.has_perm(username, "RETR"):
            self._audit.log(username, self.remote_ip, "RETR", file, "denied", "550")
            self.respond("550 Permission denied.")
            return

        safe, physical = self.authorizer.check_path_safety(username, file, self.remote_ip)
        if not safe:
            self.respond("550 Path traversal detected. Connection closed.")
            self.close()
            return

        return super().ftp_RETR(file)

    def ftp_DELE(self, file):
        username = getattr(self, "username", None)
        if not username:
            self.respond("530 Not logged in.")
            return

        if not self.authorizer.has_perm(username, "DELE"):
            self._audit.log(username, self.remote_ip, "DELE", file, "denied", "550")
            self.respond("550 Permission denied.")
            return

        safe, physical = self.authorizer.check_path_safety(username, file, self.remote_ip)
        if not safe:
            self.respond("550 Path traversal detected. Connection closed.")
            self.close()
            return

        try:
            os.remove(physical)
            self._audit.log(username, self.remote_ip, "DELE", file, "success")
            self.respond("250 Delete successful.")
        except OSError as e:
            self._audit.log(username, self.remote_ip, "DELE", file, "error", str(e))
            self.respond("550 Delete failed.")

    def ftp_RMD(self, path):
        username = getattr(self, "username", None)
        if not username:
            self.respond("530 Not logged in.")
            return

        if not self.authorizer.has_perm(username, "RMD"):
            self._audit.log(username, self.remote_ip, "RMD", path, "denied", "550")
            self.respond("550 Permission denied.")
            return

        safe, physical = self.authorizer.check_path_safety(username, path, self.remote_ip)
        if not safe:
            self.respond("550 Path traversal detected. Connection closed.")
            self.close()
            return

        try:
            shutil.rmtree(physical)
            self._audit.log(username, self.remote_ip, "RMD", path, "success")
            self.respond("250 Directory removed.")
        except OSError as e:
            self._audit.log(username, self.remote_ip, "RMD", path, "error", str(e))
            self.respond("550 Remove directory failed.")

    def ftp_MKD(self, path):
        username = getattr(self, "username", None)
        if not username:
            self.respond("530 Not logged in.")
            return

        if not self.authorizer.has_perm(username, "MKD"):
            self._audit.log(username, self.remote_ip, "MKD", path, "denied", "550")
            self.respond("550 Permission denied.")
            return

        safe, physical = self.authorizer.check_path_safety(username, path, self.remote_ip)
        if not safe:
            self.respond("550 Path traversal detected. Connection closed.")
            self.close()
            return

        try:
            os.makedirs(physical, exist_ok=True)
            self._audit.log(username, self.remote_ip, "MKD", path, "success")
            self.respond(f'257 "{path}" created.')
        except OSError as e:
            self._audit.log(username, self.remote_ip, "MKD", path, "error", str(e))
            self.respond("550 Create directory failed.")

    def ftp_LIST(self, path=""):
        username = getattr(self, "username", None)
        if not username:
            self.respond("530 Not logged in.")
            return

        if not self.authorizer.has_perm(username, "LIST"):
            self._audit.log(username, self.remote_ip, "LIST", path, "denied", "550")
            self.respond("550 Permission denied.")
            return

        return super().ftp_LIST(path)

    def ftp_REST(self, offset):
        username = getattr(self, "username", None) or "ANONYMOUS"
        try:
            self._resume_offset = int(offset)
            self._audit.log(username, self.remote_ip, "REST", str(offset), "success")
        except ValueError:
            self._audit.log(username, self.remote_ip, "REST", str(offset), "denied", "550")
            self.respond("550 Invalid REST offset.")
            return
        super().ftp_REST(offset)

    def ftp_SITE_QUOTA(self, arg):
        username = getattr(self, "username", None)
        if not username:
            self.respond("530 Not logged in.")
            return

        if not self.authorizer.has_perm(username, "SITE"):
            self._audit.log(username, self.remote_ip, "SITE_QUOTA", arg, "denied", "550")
            self.respond("550 Permission denied.")
            return

        if not arg:
            self.respond("500 Usage: SITE QUOTA <username>")
            return
        target_user = arg.strip()
        user = self._user_manager.get_user(target_user)
        if user is None:
            self.respond("550 User not found.")
            return
        usage = self._user_manager.get_usage(target_user)
        quota = user.quota_bytes
        self._audit.log(username, self.remote_ip, "SITE_QUOTA", target_user, "success")
        self.respond(
            f"200-Quota for {target_user}: {usage}/{quota} bytes "
            f"({usage / (1024*1024):.2f}MB/{quota / (1024*1024):.2f}MB)"
        )

    def ftp_SITE_INFO(self, arg):
        username = getattr(self, "username", None)
        if not username:
            self.respond("530 Not logged in.")
            return

        if not self.authorizer.has_perm(username, "SITE"):
            self._audit.log(username, self.remote_ip, "SITE_INFO", "", "denied", "550")
            self.respond("550 Permission denied.")
            return

        import sys
        active_count = 0
        try:
            active_count = len(getattr(self.server, 'connections', getattr(self.server, '_connections', [])))
        except Exception:
            active_count = 0
        info_lines = [
            "200-Server Info:",
            f"200-  Version: 1.0.0",
            f"200-  Python: {sys.version.split()[0]}",
            f"200-  Active connections: {active_count}",
            f"200-  Registered users: {len(self._user_manager.list_users())}",
        ]
        self._audit.log(username, self.remote_ip, "SITE_INFO", "", "success")
        self.respond("\r\n".join(info_lines) + "\r\n200 End.")

    def ftp_SITE_CHPERM(self, arg):
        username = getattr(self, "username", None)
        if not username:
            self.respond("530 Not logged in.")
            return

        if not self.authorizer.has_perm(username, "SITE"):
            self._audit.log(username, self.remote_ip, "SITE_CHPERM", arg, "denied", "550")
            self.respond("550 Permission denied.")
            return

        args = arg.strip().split()
        if len(args) < 2:
            self.respond("500 Usage: SITE CHPERM <username> <permissions>")
            return
        target_user = args[0]
        perms = args[1]
        valid = set(perms).issubset(
            {config.PERM_READ, config.PERM_WRITE, config.PERM_DELETE, config.PERM_ADMIN}
        )
        if not valid:
            self.respond("550 Invalid permission flags. Use: r w d a")
            return
        success = self._user_manager.set_permissions(target_user, perms)
        if success:
            self._audit.log(username, self.remote_ip, "SITE_CHPERM", f"{target_user} {perms}", "success")
            self.respond(f"200 Permissions updated for {target_user}.")
        else:
            self.respond("550 User not found.")

    def ftp_SITE_CHQUOTA(self, arg):
        username = getattr(self, "username", None)
        if not username:
            self.respond("530 Not logged in.")
            return

        if not self.authorizer.has_perm(username, "SITE"):
            self._audit.log(username, self.remote_ip, "SITE_CHQUOTA", arg, "denied", "550")
            self.respond("550 Permission denied.")
            return

        args = arg.strip().split()
        if len(args) < 2:
            self.respond("500 Usage: SITE CHQUOTA <username> <quota>")
            return
        target_user = args[0]
        quota_str = args[1]
        try:
            quota_bytes = self._parse_size(quota_str)
        except ValueError:
            self.respond("550 Invalid quota format. Use: 100M, 1G, 500K")
            return
        success = self._user_manager.set_quota(target_user, quota_bytes)
        if success:
            self._audit.log(
                username, self.remote_ip, "SITE_CHQUOTA",
                f"{target_user} {quota_str}", "success"
            )
            self.respond(f"200 Quota updated for {target_user} to {quota_str}.")
        else:
            self.respond("550 User not found.")

    @staticmethod
    def _parse_size(s: str) -> int:
        s = s.strip().upper()
        multipliers = {"K": 1024, "M": 1024**2, "G": 1024**3}
        if s[-1] in multipliers:
            return int(float(s[:-1]) * multipliers[s[-1]])
        return int(s)

    def _get_upload_size(self):
        return None

    @staticmethod
    def _check_disk_space(path):
        try:
            target_dir = os.path.dirname(path) if not os.path.isdir(path) else path
            if not os.path.exists(target_dir):
                target_dir = os.path.dirname(target_dir)
            usage = shutil.disk_usage(target_dir)
            return usage.free
        except OSError:
            return None

    def ftp_USER(self, username):
        self._audit.log(username, self.remote_ip, "USER", "", "attempt")
        super().ftp_USER(username)

    def ftp_PASS(self, password):
        username = getattr(self, "username", None) or "ANONYMOUS"
        super().ftp_PASS(password)


def create_server(host=None, port=None):
    host = host or config.FTP_HOST
    port = port or config.FTP_PORT

    os.makedirs(config.USERS_DIR, exist_ok=True)
    os.makedirs(config.TEMP_DIR, exist_ok=True)
    os.makedirs(config.AUDIT_DIR, exist_ok=True)
    os.makedirs(config.ARCHIVE_DIR, exist_ok=True)

    authorizer = CustomAuthorizer()
    CustomFTPHandler.authorizer = authorizer

    handler = CustomFTPHandler
    handler.passive_ports = config.FTP_PASSIVE_PORTS
    handler.use_sendfile = False

    server = FTPServer((host, port), handler)
    server.max_cons = 256
    server.max_cons_per_ip = 5

    return server
