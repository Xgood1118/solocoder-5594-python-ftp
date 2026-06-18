import os
from dataclasses import dataclass, field
from typing import Dict, Optional, List

from custom_authorizer import CustomAuthorizer


@dataclass
class VirtualFile:
    name: str
    physical_path: str
    is_dir: bool
    size: int = 0
    children: Dict[str, "VirtualFile"] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "is_dir": self.is_dir,
            "size": self.size,
            "children": {k: v.to_dict() for k, v in self.children.items()},
        }


class VirtualFileSystem:
    def __init__(self, authorizer: CustomAuthorizer):
        self._authorizer = authorizer

    def build_tree(self, username: str) -> Optional[VirtualFile]:
        user = self._authorizer._user_manager.get_user(username)
        if user is None:
            return None
        return self._scan_dir(user.home_dir, "/")

    def _scan_dir(self, physical_path: str, virtual_name: str) -> VirtualFile:
        is_dir = os.path.isdir(physical_path)
        size = 0
        children = {}
        if is_dir:
            try:
                for entry in os.listdir(physical_path):
                    full = os.path.join(physical_path, entry)
                    child = self._scan_dir(full, entry)
                    children[entry] = child
                    size += child.size
            except PermissionError:
                pass
        else:
            try:
                size = os.path.getsize(physical_path)
            except OSError:
                pass
        return VirtualFile(
            name=virtual_name,
            physical_path=physical_path,
            is_dir=is_dir,
            size=size,
            children=children,
        )

    def resolve_path(self, username: str, virtual_path: str) -> Optional[str]:
        user = self._authorizer._user_manager.get_user(username)
        if user is None:
            return None
        safe, physical = self._authorizer.check_path_safety(username, virtual_path)
        if not safe:
            return None
        return physical

    def list_dir(self, username: str, virtual_path: str) -> List[str]:
        physical = self.resolve_path(username, virtual_path)
        if physical is None or not os.path.isdir(physical):
            return []
        try:
            return sorted(os.listdir(physical))
        except OSError:
            return []

    def get_file_info(self, username: str, virtual_path: str) -> Optional[dict]:
        physical = self.resolve_path(username, virtual_path)
        if physical is None:
            return None
        try:
            stat = os.stat(physical)
            return {
                "name": os.path.basename(physical),
                "path": virtual_path,
                "size": stat.st_size,
                "is_dir": os.path.isdir(physical),
                "modified": stat.st_mtime,
            }
        except OSError:
            return None
