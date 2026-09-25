"""
Copy-on-Write (CoW) Ephemeral Filesystem Overlay for Agent-Hypervisor.
Ensures zero persistent contamination of developer workstations by rogue agent edits.
"""

import os
import shutil
import tempfile
from typing import Dict, List, Optional


class CopyOnWriteOverlay:
    """Manages an ephemeral CoW sandbox layer over a base workspace directory."""

    def __init__(self, base_dir: str):
        self.base_dir = os.path.abspath(base_dir)
        self.overlay_dir = tempfile.mkdtemp(prefix="hypervisor_cow_")
        self.modified_files: Dict[str, str] = {}
        self.is_active = True

    def get_effective_path(self, relative_path: str) -> str:
        """Returns the overlay path if modified, or points into base workspace."""
        overlay_target = os.path.join(self.overlay_dir, relative_path)
        if os.path.exists(overlay_target):
            return overlay_target
        return os.path.join(self.base_dir, relative_path)

    def write_file(self, relative_path: str, content: str) -> str:
        """Writes file strictly into ephemeral overlay, preserving base file."""
        overlay_path = os.path.join(self.overlay_dir, relative_path)
        os.makedirs(os.path.dirname(overlay_path), exist_ok=True)
        with open(overlay_path, "w", encoding="utf-8") as f:
            f.write(content)
        self.modified_files[relative_path] = overlay_path
        return overlay_path

    def read_file(self, relative_path: str) -> Optional[str]:
        """Reads effective file content (overlay takes priority over base)."""
        eff_path = self.get_effective_path(relative_path)
        if os.path.exists(eff_path):
            with open(eff_path, "r", encoding="utf-8") as f:
                return f.read()
        return None

    def commit(self) -> List[str]:
        """Flushes overlay modifications back into the base directory."""
        committed = []
        for rel_path, overlay_path in self.modified_files.items():
            base_target = os.path.join(self.base_dir, rel_path)
            os.makedirs(os.path.dirname(base_target), exist_ok=True)
            shutil.copy2(overlay_path, base_target)
            committed.append(rel_path)
        self.discard()
        return committed

    def discard(self) -> None:
        """Purges ephemeral overlay directory completely with zero host footprint."""
        if os.path.exists(self.overlay_dir):
            shutil.rmtree(self.overlay_dir, ignore_errors=True)
        self.modified_files.clear()
        self.is_active = False
