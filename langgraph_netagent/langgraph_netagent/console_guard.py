"""Console input guard for Windows terminals.

Root cause this module fixes:
    Detection/probing code spawns ``wsl.exe`` / ``powershell`` / ``docker`` via
    ``subprocess.run`` without redirecting stdin. The children inherit the
    console input handle; ``wsl.exe`` switches it to raw/VT mode and, when it is
    killed by a timeout, never restores it. Afterwards ``input()`` no longer
    echoes or accepts line input, so the REPL looks "frozen".

Two defences:
    1. ``install()`` makes ``subprocess.run`` default to ``stdin=DEVNULL`` so child
       processes can never touch the interactive console.
    2. ``restore_console()`` re-applies a sane console mode and flushes stray
       input events; call it right before every prompt.
"""

from __future__ import annotations

import subprocess
import sys

_ORIGINAL_RUN = subprocess.run
_INSTALLED = False
_SAVED_MODE = None  # type: ignore[var-annotated]

# Standard cooked-mode flags: PROCESSED | LINE | ECHO | INSERT | EXTENDED_FLAGS
# (QuickEdit 0x0040 intentionally excluded so mouse clicks cannot pause the app)
_COOKED_MODE = 0x0001 | 0x0002 | 0x0004 | 0x0020 | 0x0080


def _get_stdin_handle():
    import ctypes

    return ctypes.windll.kernel32.GetStdHandle(-10)  # STD_INPUT_HANDLE


def _safe_run(*args, **kwargs):
    if "stdin" not in kwargs and "input" not in kwargs:
        kwargs["stdin"] = subprocess.DEVNULL
    return _ORIGINAL_RUN(*args, **kwargs)


def install() -> None:
    """Patch subprocess.run and snapshot the current console input mode."""
    global _INSTALLED, _SAVED_MODE
    if _INSTALLED:
        return
    subprocess.run = _safe_run  # type: ignore[assignment]
    _INSTALLED = True

    if sys.platform != "win32" or not sys.stdin or not sys.stdin.isatty():
        return
    try:
        import ctypes

        mode = ctypes.c_uint32()
        if ctypes.windll.kernel32.GetConsoleMode(_get_stdin_handle(), ctypes.byref(mode)):
            # Keep the user's flags, but guarantee line input + echo, drop QuickEdit.
            _SAVED_MODE = (mode.value | _COOKED_MODE) & ~0x0040
    except Exception:
        _SAVED_MODE = None


def restore_console() -> None:
    """Restore cooked console input mode and drop pending junk input events."""
    if sys.platform != "win32" or not sys.stdin or not sys.stdin.isatty():
        return
    try:
        import ctypes

        k32 = ctypes.windll.kernel32
        handle = _get_stdin_handle()
        k32.SetConsoleMode(handle, _SAVED_MODE if _SAVED_MODE is not None else _COOKED_MODE)
        k32.FlushConsoleInputBuffer(handle)
    except Exception:
        pass
