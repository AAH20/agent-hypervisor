"""
agent-hypervisor: Zero-Trust System Call Interceptor & Userspace Virtualization Shield for OS-Level Coding Agents.
"""

from .models import (
    SyscallType,
    SecurityPolicy,
    SyscallEvent,
    HypervisorExecutionResult,
)
from .policy_engine import ZeroTrustPolicyEngine
from .cow_sandbox import CopyOnWriteOverlay
from .hypervisor_core import AgentHypervisor

__version__ = "0.1.0"
__all__ = [
    "SyscallType",
    "SecurityPolicy",
    "SyscallEvent",
    "HypervisorExecutionResult",
    "ZeroTrustPolicyEngine",
    "CopyOnWriteOverlay",
    "AgentHypervisor",
]
