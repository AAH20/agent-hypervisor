"""
Hypervisor Core Gateway & Command Interceptor for Agent-Hypervisor.
Wraps agent bash invocations and intercepts dangerous operations before execution.
"""

import subprocess
import time
from typing import Optional, List
from .models import SecurityPolicy, HypervisorExecutionResult, SyscallEvent
from .policy_engine import ZeroTrustPolicyEngine
from .cow_sandbox import CopyOnWriteOverlay


class AgentHypervisor:
    """Userspace hypervisor for autonomous coding agents (Claude Opus 5.5, GPT-6 Astra)."""

    def __init__(self, workspace_dir: str = ".", policy: Optional[SecurityPolicy] = None):
        self.workspace_dir = workspace_dir
        self.policy = policy or SecurityPolicy()
        self.policy_engine = ZeroTrustPolicyEngine(self.policy)
        self.cow_overlay = CopyOnWriteOverlay(workspace_dir)

    def execute_command(self, cmd_line: str, auto_discard_on_error: bool = True) -> HypervisorExecutionResult:
        """
        Intercepts and evaluates command before running.
        Blocks execution if any security policy violation is found.
        """
        start_time = time.time()

        # Step 1: Pre-flight Syscall Inspection
        events = self.policy_engine.inspect_command(cmd_line)
        blocked_events = [e for e in events if e.is_blocked]

        if blocked_events:
            duration_ms = (time.time() - start_time) * 1000.0
            reasons = "; ".join([e.violation_reason or "Blocked by hypervisor" for e in blocked_events])
            return HypervisorExecutionResult(
                command=cmd_line,
                exit_code=126,  # Standard permission denied / blocked exit code
                stdout="",
                stderr=f"EPERM: Syscall blocked by Agent-Hypervisor policy: {reasons}",
                intercepted_events=events,
                violations_count=len(blocked_events),
                duration_ms=duration_ms,
                was_isolated=True,
                cow_discarded=False
            )

        # Step 2: Hermetic Execution in CoW Overlay
        proc = subprocess.run(
            cmd_line,
            shell=True,
            cwd=self.cow_overlay.overlay_dir,
            capture_output=True,
            text=True
        )

        duration_ms = (time.time() - start_time) * 1000.0
        discarded = False
        if proc.returncode != 0 and auto_discard_on_error:
            self.cow_overlay.discard()
            discarded = True

        return HypervisorExecutionResult(
            command=cmd_line,
            exit_code=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            intercepted_events=events,
            violations_count=0,
            duration_ms=duration_ms,
            was_isolated=True,
            cow_discarded=discarded
        )
