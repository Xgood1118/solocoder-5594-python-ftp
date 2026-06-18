import os
import shutil
import uuid
import threading

import config
from audit_logger import AuditLogger


class ChunkHandler:
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
        os.makedirs(config.TEMP_DIR, exist_ok=True)
        self._transfers = {}
        self._audit = AuditLogger()

    def is_chunked(self, file_size: int) -> bool:
        return file_size > config.CHUNK_THRESHOLD

    def create_transfer(self, username: str, target_path: str, total_size: int) -> str:
        transfer_id = uuid.uuid4().hex[:16]
        temp_dir = os.path.join(config.TEMP_DIR, transfer_id)
        os.makedirs(temp_dir, exist_ok=True)
        self._transfers[transfer_id] = {
            "id": transfer_id,
            "username": username,
            "target_path": target_path,
            "total_size": total_size,
            "temp_dir": temp_dir,
            "chunks_received": 0,
            "bytes_received": 0,
            "completed": False,
        }
        return transfer_id

    def write_chunk(self, transfer_id: str, chunk_data: bytes, chunk_index: int) -> bool:
        transfer = self._transfers.get(transfer_id)
        if transfer is None:
            return False
        chunk_path = os.path.join(transfer["temp_dir"], f"chunk_{chunk_index:06d}")
        try:
            with open(chunk_path, "wb") as f:
                f.write(chunk_data)
            transfer["chunks_received"] += 1
            transfer["bytes_received"] += len(chunk_data)
            return True
        except OSError:
            return False

    def append_chunk(self, transfer_id: str, data: bytes) -> bool:
        transfer = self._transfers.get(transfer_id)
        if transfer is None:
            return False
        chunk_index = transfer["chunks_received"]
        chunk_path = os.path.join(transfer["temp_dir"], f"chunk_{chunk_index:06d}")
        try:
            with open(chunk_path, "wb") as f:
                f.write(data)
            transfer["chunks_received"] += 1
            transfer["bytes_received"] += len(data)
            return True
        except OSError:
            return False

    def merge_chunks(self, transfer_id: str) -> bool:
        transfer = self._transfers.get(transfer_id)
        if transfer is None:
            return False
        temp_dir = transfer["temp_dir"]
        target_path = transfer["target_path"]
        chunk_files = sorted(
            f for f in os.listdir(temp_dir) if f.startswith("chunk_")
        )
        target_dir = os.path.dirname(target_path)
        os.makedirs(target_dir, exist_ok=True)
        try:
            with open(target_path, "wb") as out_f:
                for chunk_file in chunk_files:
                    chunk_path = os.path.join(temp_dir, chunk_file)
                    with open(chunk_path, "rb") as in_f:
                        shutil.copyfileobj(in_f, out_f)
            transfer["completed"] = True
            self._audit.log(
                transfer["username"],
                "0.0.0.0",
                "CHUNK_MERGE",
                target_path,
                "success",
            )
            self._cleanup_transfer(transfer_id)
            return True
        except OSError as e:
            self._audit.log(
                transfer["username"],
                "0.0.0.0",
                "CHUNK_MERGE",
                target_path,
                "error",
                str(e),
            )
            return False

    def get_transfer(self, transfer_id: str) -> dict:
        return self._transfers.get(transfer_id)

    def cancel_transfer(self, transfer_id: str):
        self._cleanup_transfer(transfer_id)

    def _cleanup_transfer(self, transfer_id: str):
        transfer = self._transfers.pop(transfer_id, None)
        if transfer is None:
            return
        temp_dir = transfer["temp_dir"]
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)

    def get_temp_file_size(self, transfer_id: str) -> int:
        transfer = self._transfers.get(transfer_id)
        if transfer is None:
            return 0
        total = 0
        temp_dir = transfer["temp_dir"]
        if not os.path.exists(temp_dir):
            return 0
        for chunk_file in sorted(os.listdir(temp_dir)):
            if chunk_file.startswith("chunk_"):
                try:
                    total += os.path.getsize(os.path.join(temp_dir, chunk_file))
                except OSError:
                    pass
        return total

    def validate_resume_offset(self, transfer_id: str, client_offset: int) -> bool:
        actual_size = self.get_temp_file_size(transfer_id)
        if client_offset < 0:
            return False
        if client_offset > actual_size:
            return False
        return True
