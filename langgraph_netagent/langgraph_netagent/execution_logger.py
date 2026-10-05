"""Execution Logger and Audit Tracer for LangGraph NetAgent Workflows.

Provides structured execution tracing across LangGraph workflow nodes, AAL tool invocations,
and general network automation modules:
- Tracks calling module / node name
- Tracks execution timestamps (start_time, end_time, duration)
- Captures sanitized input parameters and state snapshots
- Captures output return values and incremental state updates
- Records execution status (success, error details, stack traces)
- Persists structured JSONL logs to disk with thread-safe file handling
"""

from __future__ import annotations

from datetime import datetime, timezone
import functools
import inspect
import json
import os
from pathlib import Path
import threading
import traceback
from typing import Any, Callable, Dict, List, Optional, Union
from pydantic import BaseModel


def safe_serialize(obj: Any, max_depth: int = 6, _current_depth: int = 0) -> Any:
    """Recursively serialize arbitrary Python and Pydantic objects to JSON-compatible data.
    
    Protects against infinite recursion, unpicklable objects, circular references,
    and converts non-serializable objects (datetime, Enum, Path, Exception, etc.) gracefully.
    """
    if _current_depth > max_depth:
        return f"<Truncated: max recursion depth {max_depth} reached>"

    if obj is None or isinstance(obj, (bool, int, float, str)):
        return obj

    # Handle Pydantic v2 / v1 models
    if hasattr(obj, "model_dump") and callable(getattr(obj, "model_dump")):
        try:
            return safe_serialize(obj.model_dump(mode="json"), max_depth, _current_depth + 1)
        except Exception:
            try:
                return safe_serialize(obj.model_dump(), max_depth, _current_depth + 1)
            except Exception:
                pass
    elif hasattr(obj, "dict") and callable(getattr(obj, "dict")):
        try:
            return safe_serialize(obj.dict(), max_depth, _current_depth + 1)
        except Exception:
            pass

    # Datetime / Date
    if isinstance(obj, datetime):
        return obj.isoformat()
    if hasattr(obj, "isoformat") and callable(getattr(obj, "isoformat")):
        try:
            return obj.isoformat()
        except Exception:
            pass

    # Path
    if isinstance(obj, Path):
        return str(obj)

    # Exceptions
    if isinstance(obj, BaseException):
        return {"error_type": type(obj).__name__, "error_message": str(obj)}

    # Enums
    if hasattr(obj, "value"):
        return safe_serialize(obj.value, max_depth, _current_depth + 1)

    # Bytes
    if isinstance(obj, (bytes, bytearray)):
        try:
            return obj.decode("utf-8")
        except Exception:
            return f"<bytes len={len(obj)}>"

    # Dictionaries
    if isinstance(obj, dict):
        sanitized_dict: Dict[str, Any] = {}
        for k, v in obj.items():
            key_str = str(k)
            sanitized_dict[key_str] = safe_serialize(v, max_depth, _current_depth + 1)
        return sanitized_dict

    # Iterables: lists, tuples, sets
    if isinstance(obj, (list, tuple, set)):
        return [safe_serialize(item, max_depth, _current_depth + 1) for item in obj]

    # Custom objects with __dict__
    if hasattr(obj, "__dict__"):
        try:
            return {
                k: safe_serialize(v, max_depth, _current_depth + 1)
                for k, v in obj.__dict__.items()
                if not k.startswith("_")
            }
        except Exception:
            pass

    # Final fallback to string representation
    return str(obj)


class ExecutionLogEntry(BaseModel):
    """Structured execution trace record capturing module invocation, timing, inputs, and outputs."""
    timestamp: str
    node_name: str
    module: str
    function_name: str
    start_time: str
    end_time: str
    duration_seconds: float
    duration_ms: float
    input_state: Optional[Dict[str, Any]] = None
    input_args: Optional[List[Any]] = None
    input_kwargs: Optional[Dict[str, Any]] = None
    output_state_update: Optional[Any] = None
    success: bool = True
    error: Optional[str] = None
    traceback: Optional[str] = None


class ExecutionLogger:
    """Centralized thread-safe execution audit logger.
    
    Guarantees that every wrapped node or function captures:
    - Target module and node name
    - Precise start, end, and duration timestamps
    - Complete input snapshot / arguments
    - Complete output updates / return value
    - Exception information on failure
    """

    _instance: Optional["ExecutionLogger"] = None
    _lock = threading.Lock()

    def __init__(self, log_file: Optional[Union[str, Path]] = None, enabled: bool = True):
        self._enabled = enabled
        self._write_lock = threading.Lock()
        
        if log_file:
            self._log_file = Path(log_file).resolve()
        else:
            env_file = os.environ.get("NETAGENT_LOG_FILE")
            if env_file:
                self._log_file = Path(env_file).resolve()
            else:
                env_dir = os.environ.get("NETAGENT_LOG_DIR")
                base_dir = Path(env_dir).resolve() if env_dir else Path.cwd() / "exported_logs"
                self._log_file = base_dir / "node_execution_logs.jsonl"

    @classmethod
    def get_instance(cls) -> "ExecutionLogger":
        """Get or initialize the global singleton logger."""
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    @property
    def log_file(self) -> Path:
        return self._log_file

    def configure(
        self,
        log_file: Optional[Union[str, Path]] = None,
        enabled: Optional[bool] = None,
    ) -> None:
        """Dynamically configure log destination and active status."""
        with self._write_lock:
            if log_file is not None:
                self._log_file = Path(log_file).resolve()
            if enabled is not None:
                self._enabled = enabled

    def log(self, entry: Union[ExecutionLogEntry, Dict[str, Any]]) -> None:
        """Write an execution trace entry to the JSONL file."""
        if not self._enabled:
            return

        if isinstance(entry, ExecutionLogEntry):
            record = entry.model_dump()
        else:
            record = entry

        safe_record = safe_serialize(record)

        try:
            self._log_file.parent.mkdir(parents=True, exist_ok=True)
            with self._write_lock:
                with open(self._log_file, "a", encoding="utf-8") as f:
                    f.write(json.dumps(safe_record, ensure_ascii=False) + "\n")
        except Exception as exc:
            # Fallback to stderr without crashing the operational workflow
            try:
                import sys
                sys.stderr.write(f"[ExecutionLogger Error] Failed to write log: {exc}\n")
            except Exception:
                pass

    def wrap_node(
        self,
        name: str,
        node_fn: Callable[[Any], Dict[str, Any]],
        module_name: Optional[str] = None,
    ) -> Callable[[Any], Dict[str, Any]]:
        """Wrap a LangGraph workflow node to capture timing, input state, and output updates."""
        resolved_module = module_name or getattr(node_fn, "__module__", "workflow")

        @functools.wraps(node_fn)
        def logged_node(state: Any) -> Dict[str, Any]:
            start_dt = datetime.now(timezone.utc)
            start_time = start_dt.isoformat()
            
            # Capture snapshot of input state
            input_snapshot: Optional[Dict[str, Any]] = None
            if isinstance(state, dict):
                input_snapshot = safe_serialize(dict(state))
            elif hasattr(state, "__dict__"):
                input_snapshot = safe_serialize(dict(state.__dict__))

            result: Optional[Dict[str, Any]] = None
            exc_obj: Optional[Exception] = None
            exc_tb: Optional[str] = None

            try:
                result = node_fn(state)
                return result
            except Exception as exc:
                exc_obj = exc
                exc_tb = traceback.format_exc()
                raise
            finally:
                end_dt = datetime.now(timezone.utc)
                end_time = end_dt.isoformat()
                duration_sec = (end_dt - start_dt).total_seconds()
                duration_ms = duration_sec * 1000.0

                log_entry = {
                    # Standard compatibility fields
                    "timestamp": end_time,
                    "node_name": name,
                    "start_time": start_time,
                    "end_time": end_time,
                    "output_state_update": safe_serialize(result) if result is not None else None,
                    # Comprehensive execution audit fields
                    "module": resolved_module,
                    "function_name": getattr(node_fn, "__name__", name),
                    "duration_seconds": round(duration_sec, 6),
                    "duration_ms": round(duration_ms, 3),
                    "input_state": input_snapshot,
                    "success": exc_obj is None,
                    "error": str(exc_obj) if exc_obj else None,
                    "traceback": exc_tb,
                }
                self.log(log_entry)

        return logged_node

    def wrap_nodes(
        self,
        nodes: Dict[str, Callable[[Any], Dict[str, Any]]],
        module_name: Optional[str] = None,
    ) -> Dict[str, Callable[[Any], Dict[str, Any]]]:
        """Wrap all nodes in a dictionary with execution logging."""
        return {
            name: self.wrap_node(name, fn, module_name=module_name)
            for name, fn in nodes.items()
        }

    def trace(
        self,
        module: Optional[str] = None,
        name: Optional[str] = None,
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Decorator for tracing arbitrary functions (capturing args, kwargs, return value, timing)."""
        def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            resolved_module = module or getattr(fn, "__module__", "unknown")
            resolved_name = name or getattr(fn, "__name__", "unnamed")

            @functools.wraps(fn)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                start_dt = datetime.now(timezone.utc)
                start_time = start_dt.isoformat()

                # Capture sanitized inputs
                input_args = safe_serialize(list(args))
                input_kwargs = safe_serialize(dict(kwargs))

                result: Any = None
                exc_obj: Optional[Exception] = None
                exc_tb: Optional[str] = None

                try:
                    result = fn(*args, **kwargs)
                    return result
                except Exception as exc:
                    exc_obj = exc
                    exc_tb = traceback.format_exc()
                    raise
                finally:
                    end_dt = datetime.now(timezone.utc)
                    end_time = end_dt.isoformat()
                    duration_sec = (end_dt - start_dt).total_seconds()
                    duration_ms = duration_sec * 1000.0

                    log_entry = {
                        "timestamp": end_time,
                        "node_name": resolved_name,
                        "module": resolved_module,
                        "function_name": getattr(fn, "__name__", resolved_name),
                        "start_time": start_time,
                        "end_time": end_time,
                        "duration_seconds": round(duration_sec, 6),
                        "duration_ms": round(duration_ms, 3),
                        "input_args": input_args,
                        "input_kwargs": input_kwargs,
                        "output": safe_serialize(result),
                        "success": exc_obj is None,
                        "error": str(exc_obj) if exc_obj else None,
                        "traceback": exc_tb,
                    }
                    self.log(log_entry)

            return wrapper
        return decorator

    def log_tool_execution(
        self,
        tool_name: str,
        node_name: str,
        command: str,
        read_only: bool = False,
        step_tag: str = "",
        success: bool = True,
        exit_code: int = 0,
        is_blocked: bool = False,
        output: Any = None,
        error: Optional[str] = None,
    ) -> None:
        """Log a tool or network device command execution to the audit log."""
        now = datetime.now(timezone.utc).isoformat()
        log_entry = {
            "timestamp": now,
            "node_name": node_name,
            "module": "tools.aal",
            "function_name": f"aal_tool:{tool_name}",
            "start_time": now,
            "end_time": now,
            "duration_seconds": 0.0,
            "duration_ms": 0.0,
            "input_args": [command],
            "input_kwargs": {
                "tool_name": tool_name,
                "node_name": node_name,
                "read_only": read_only,
                "step_tag": step_tag,
            },
            "output": safe_serialize(output),
            "success": success and not is_blocked,
            "error": error,
            "is_blocked": is_blocked,
            "exit_code": exit_code,
        }
        self.log(log_entry)

    def get_recent_logs(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Read the most recent execution log entries from the JSONL file."""
        if not self._log_file.exists():
            return []
        entries: List[Dict[str, Any]] = []
        try:
            with open(self._log_file, "r", encoding="utf-8") as f:
                for line in f:
                    line_str = line.strip()
                    if line_str:
                        try:
                            entries.append(json.loads(line_str))
                        except Exception:
                            pass
        except Exception:
            return []
        return entries[-limit:]

    def clear_logs(self) -> None:
        """Clear the current execution log file (useful for testing and reset)."""
        with self._write_lock:
            if self._log_file.exists():
                try:
                    with open(self._log_file, "w", encoding="utf-8") as f:
                        f.truncate(0)
                except Exception:
                    pass


# Global singleton access helpers
def get_execution_logger() -> ExecutionLogger:
    """Return the global ExecutionLogger singleton instance."""
    return ExecutionLogger.get_instance()


def log_execution(module: Optional[str] = None, name: Optional[str] = None) -> Callable:
    """Decorator to trace execution of any function, logging inputs, outputs, and timing."""
    return get_execution_logger().trace(module=module, name=name)


def wrap_logged_nodes(
    nodes: Dict[str, Callable[[Any], Dict[str, Any]]],
    module_name: Optional[str] = None,
) -> Dict[str, Callable[[Any], Dict[str, Any]]]:
    """Wrap a dictionary of workflow nodes with execution logging."""
    return get_execution_logger().wrap_nodes(nodes, module_name=module_name)
