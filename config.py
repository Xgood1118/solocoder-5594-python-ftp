import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

FTP_HOST = "0.0.0.0"
FTP_PORT = 8144
FTP_PASSIVE_PORTS = range(60000, 60100)

DATA_DIR = os.path.join(BASE_DIR, "data")
USERS_DIR = os.path.join(DATA_DIR, "users")
TEMP_DIR = os.path.join(DATA_DIR, "temp")
AUDIT_DIR = os.path.join(DATA_DIR, "audit")
ARCHIVE_DIR = os.path.join(DATA_DIR, "archive")

USERS_DB = os.path.join(DATA_DIR, "users.json")

CHUNK_THRESHOLD = 50 * 1024 * 1024
CHUNK_SIZE = 10 * 1024 * 1024

MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = 300

AUDIT_MAX_BYTES = 100 * 1024 * 1024
AUDIT_BACKUP_COUNT = 0
ARCHIVE_RETENTION_DAYS = 90

PERM_READ = "r"
PERM_WRITE = "w"
PERM_DELETE = "d"
PERM_ADMIN = "a"

PERM_MAP = {
    PERM_READ: {"LIST", "RETR", "NLST", "SIZE", "MDTM", "STAT", "MLSD", "MLST"},
    PERM_WRITE: {"STOR", "APPE", "MKD", "CWD", "PWD", "CDUP", "RNFR", "RNTO"},
    PERM_DELETE: {"RMD", "DELE"},
    PERM_ADMIN: {"SITE"},
}
