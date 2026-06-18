import json
import logging
import logging.handlers
import os
import gzip
import shutil
import threading
from datetime import datetime

import config


class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_entry = getattr(record, "audit_data", None)
        if log_entry is None:
            log_entry = {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "level": record.levelname,
                "message": record.getMessage(),
            }
        return json.dumps(log_entry, ensure_ascii=False)


class AuditLogger:
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
        os.makedirs(config.AUDIT_DIR, exist_ok=True)
        os.makedirs(config.ARCHIVE_DIR, exist_ok=True)

        self._logger = logging.getLogger("ftp_audit")
        self._logger.setLevel(logging.INFO)
        self._logger.propagate = False

        self._log_file = os.path.join(config.AUDIT_DIR, "audit.jsonl")
        self._handler = logging.handlers.RotatingFileHandler(
            self._log_file,
            maxBytes=config.AUDIT_MAX_BYTES,
            backupCount=config.AUDIT_BACKUP_COUNT,
            encoding="utf-8",
        )
        self._handler.setFormatter(JsonFormatter())
        self._logger.addHandler(self._handler)

        self._archiver_thread = None

    def log(self, username, client_ip, operation, target_path="", result="success", error_code=None):
        audit_data = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "user": username,
            "client_ip": client_ip,
            "operation": operation,
            "target_path": target_path,
            "result": result,
        }
        if error_code is not None:
            audit_data["error_code"] = error_code
        record = logging.LogRecord(
            name="ftp_audit",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="",
            args=(),
            exc_info=None,
        )
        record.audit_data = audit_data
        self._logger.handle(record)

    def start_archiver(self, interval_hours=24):
        def _archive_loop():
            import time
            while True:
                time.sleep(interval_hours * 3600)
                self._do_archive()

        self._archiver_thread = threading.Thread(target=_archive_loop, daemon=True)
        self._archiver_thread.start()

    def _do_archive(self):
        if not os.path.exists(self._log_file):
            return
        now = datetime.utcnow()
        archive_name = f"audit_{now.strftime('%Y%m%d_%H%M%S')}.jsonl.gz"
        archive_path = os.path.join(config.ARCHIVE_DIR, archive_name)

        for handler in self._logger.handlers[:]:
            handler.close()
            self._logger.removeHandler(handler)

        with open(self._log_file, "rb") as f_in:
            with gzip.open(archive_path, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)

        open(self._log_file, "w").close()

        self._handler = logging.handlers.RotatingFileHandler(
            self._log_file,
            maxBytes=config.AUDIT_MAX_BYTES,
            backupCount=config.AUDIT_BACKUP_COUNT,
            encoding="utf-8",
        )
        self._handler.setFormatter(JsonFormatter())
        self._logger.addHandler(self._handler)

        self.log(
            username="SYSTEM",
            client_ip="0.0.0.0",
            operation="ARCHIVE",
            target_path=archive_path,
            result="success",
        )

        self._cleanup_old_archives()

    def _cleanup_old_archives(self):
        now = datetime.utcnow()
        for fname in os.listdir(config.ARCHIVE_DIR):
            fpath = os.path.join(config.ARCHIVE_DIR, fname)
            if not os.path.isfile(fpath):
                continue
            mtime = datetime.utcfromtimestamp(os.path.getmtime(fpath))
            age_days = (now - mtime).days
            if age_days > config.ARCHIVE_RETENTION_DAYS:
                os.remove(fpath)
                self.log(
                    username="SYSTEM",
                    client_ip="0.0.0.0",
                    operation="ARCHIVE_CLEANUP",
                    target_path=fpath,
                    result="success",
                )
