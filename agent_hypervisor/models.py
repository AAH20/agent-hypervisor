"""
Data models and security policy definitions for Agent-Hypervisor.
Zero-Trust System Call Interceptor & Userspace Virtualization Shield for OS-Level Coding Agents.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any
import time


class SyscallType(str, Enum):
    EXECVE = "EXECVE"
    OPENAT_READ = "OPENAT_READ"
    OPENAT_WRITE = "OPENAT_WRITE"
    CONNECT_NETWORK = "CONNECT_NETWORK"
    UNLINK = "UNLINK"


@dataclass
class SecurityPolicy:
    allow_network_egress: bool = False
    allowed_domains: List[str] = field(default_factory=lambda: ["pypi.org", "github.com"])
    forbidden_paths: List[str] = field(default_factory=lambda: [
        ".env", "/etc/shadow", "/etc/passwd", "~/.ssh", "~/.aws", ".git/config"
    ])
    blocked_commands: List[str] = field(default_factory=lambda: [
        "rm -rf /", "mkfs", ":(){ :|:& };:", "dd if=/dev/zero"
    ])
    enforce_cow_filesystem: bool = True


@dataclass
class SyscallEvent:
    syscall_type: SyscallType
    target: str
    arguments: List[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)
    is_blocked: bool = False
    violation_reason: Optional[str] = None


@dataclass
class HypervisorExecutionResult:
    command: str
    exit_code: int
    stdout: str
    stderr: str
    intercepted_events: List[SyscallEvent] = field(default_factory=list)
    violations_count: int = 0
    duration_ms: float = 0.0
    was_isolated: bool = True
    cow_discarded: bool = False
