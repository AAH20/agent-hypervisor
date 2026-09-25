"""
Zero-Trust Policy Engine & Syscall Analyzer for Agent-Hypervisor.
"""

import os
import re
import shlex
from typing import List, Tuple, Optional
from .models import SecurityPolicy, SyscallType, SyscallEvent


class ZeroTrustPolicyEngine:
    """Evaluates commands and simulated syscalls against fine-grained security policies."""

    def __init__(self, policy: Optional[SecurityPolicy] = None):
        self.policy = policy or SecurityPolicy()

    def inspect_command(self, cmd_line: str) -> List[SyscallEvent]:
        """Inspect a shell command line and detect underlying simulated system calls."""
        events: List[SyscallEvent] = []

        try:
            tokens = shlex.split(cmd_line)
        except Exception:
            tokens = cmd_line.split()

        if not tokens:
            return events

        binary = tokens[0]

        # 1. Inspect EXECVE
        is_blocked_cmd = False
        violation_cmd = None
        for blocked in self.policy.blocked_commands:
            if blocked in cmd_line:
                is_blocked_cmd = True
                violation_cmd = f"Command matches blocked catastrophic pattern: '{blocked}'"
                break

        events.append(SyscallEvent(
            syscall_type=SyscallType.EXECVE,
            target=binary,
            arguments=tokens[1:],
            is_blocked=is_blocked_cmd,
            violation_reason=violation_cmd
        ))

        # 2. Inspect File Access (OPENAT / UNLINK)
        for token in tokens:
            # Check for forbidden files (e.g. .env, ~/.ssh)
            for forbidden in self.policy.forbidden_paths:
                norm_token = os.path.expanduser(token)
                norm_forbidden = os.path.expanduser(forbidden)
                if norm_forbidden in norm_token or token == forbidden:
                    events.append(SyscallEvent(
                        syscall_type=SyscallType.OPENAT_READ,
                        target=token,
                        arguments=[],
                        is_blocked=True,
                        violation_reason=f"Access to sensitive path forbidden by policy: '{forbidden}'"
                    ))

            # Check for unlinks
            if binary in ("rm", "unlink") and token not in ("-rf", "-f", "-r", binary):
                if "/" in token and len(token) <= 2:
                    events.append(SyscallEvent(
                        syscall_type=SyscallType.UNLINK,
                        target=token,
                        arguments=[],
                        is_blocked=True,
                        violation_reason="Critical system path unlinking blocked"
                    ))

        # 3. Inspect Network Socket / Egress (CONNECT_NETWORK)
        if binary in ("curl", "wget", "nc", "telnet", "ssh", "ncat"):
            # Check if network is allowed or target domain is whitelisted
            url_match = re.search(r"https?://([a-zA-Z0-9.\-_]+)", cmd_line)
            target_host = url_match.group(1) if url_match else "unknown_egress"

            is_blocked_net = False
            violation_net = None

            if not self.policy.allow_network_egress:
                if target_host not in self.policy.allowed_domains:
                    is_blocked_net = True
                    violation_net = f"Unauthorized egress destination '{target_host}'. Not in whitelisted domains."

            events.append(SyscallEvent(
                syscall_type=SyscallType.CONNECT_NETWORK,
                target=target_host,
                arguments=tokens[1:],
                is_blocked=is_blocked_net,
                violation_reason=violation_net
            ))

        return events
