"""Safe async wrapper for shelling out to optional external recon tools.

Every scanner module tries a real binary (subfinder, httpx, katana, ...) first
and transparently falls back to a pure-Python implementation if the binary is
not installed. Nothing here ever passes user input directly into a shell
string -- args are always passed as a list to avoid shell injection.
"""
from __future__ import annotations

import asyncio
import shutil
from dataclasses import dataclass

from app.logging_config import get_logger

logger = get_logger(__name__)


@dataclass
class ToolResult:
    ok: bool
    stdout: str = ""
    stderr: str = ""
    used_fallback: bool = False


def tool_available(binary: str) -> bool:
    return shutil.which(binary) is not None


async def run_tool(args: list[str], timeout: int = 120) -> ToolResult:
    """Run an external CLI tool safely. Returns ToolResult; never raises."""
    binary = args[0]
    if not tool_available(binary):
        logger.info("External tool '%s' not found on PATH; caller should use fallback.", binary)
        return ToolResult(ok=False, used_fallback=True)

    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return ToolResult(
            ok=proc.returncode == 0,
            stdout=stdout.decode(errors="ignore"),
            stderr=stderr.decode(errors="ignore"),
        )
    except asyncio.TimeoutError:
        logger.warning("Tool '%s' timed out after %ss", binary, timeout)
        return ToolResult(ok=False, stderr="timeout")
    except Exception as exc:  # noqa: BLE001
        logger.exception("Tool '%s' failed to execute", binary)
        return ToolResult(ok=False, stderr=str(exc))
