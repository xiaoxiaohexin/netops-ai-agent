"""Robust JSON Extractor, Sanitizer, and Self-Healing Schema Validator."""

from __future__ import annotations
import ast
import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple, Type, TypeVar
from pydantic import BaseModel, ValidationError

logger = logging.getLogger(__name__)
T = TypeVar("T", bound=BaseModel)


def extract_json_substring(text: str) -> str:
    """Extract raw JSON text from markdown code blocks or balanced braces.

    1. Iterates candidate markdown code blocks (prioritizing ```json over generic ```).
    2. Validates candidates to ensure they contain actual JSON structures.
    3. If no code block yields valid JSON, scans full text for balanced { ... } or [ ... ]
       that represent JSON structures (skipping conversational braces like {1}).
    4. Tracks string literals and escape characters to prevent premature truncation
       when backticks or braces appear inside JSON strings.
    """
    if not text or not text.strip():
        raise ValueError("Input text is empty, cannot extract JSON")

    trimmed = text.strip()

    def _is_valid_or_plausible_json(candidate: str) -> bool:
        """Check if candidate string is valid or structurally plausible JSON."""
        c = candidate.strip()
        if not c:
            return False
        # Must start and end with matching brackets
        if c.startswith("{") and c.endswith("}"):
            if c == "{}":
                return True
            # In JSON, an object MUST contain key-value pairs with ':'
            if ":" not in c:
                return False
            # Try strict parse
            try:
                val = json.loads(c)
                return isinstance(val, dict)
            except Exception:
                pass
            # Try parsing with trailing comma removal
            sanitized = re.sub(r",\s*([\}\]])", r"\1", c)
            try:
                val = json.loads(sanitized)
                return isinstance(val, dict)
            except Exception:
                pass
            # Structural fallback: has quotes (single or double) and colon
            return ('"' in c or "'" in c) and ":" in c

        elif c.startswith("[") and c.endswith("]"):
            if c == "[]":
                return True
            try:
                val = json.loads(c)
                return isinstance(val, list)
            except Exception:
                pass
            sanitized = re.sub(r",\s*([\}\]])", r"\1", c)
            try:
                val = json.loads(sanitized)
                return isinstance(val, list)
            except Exception:
                pass
            return False

        return False

    def _scan_balanced_in_text(source: str) -> List[Tuple[int, int, str]]:
        """Find all balanced outermost JSON candidates (curly or square) in source."""
        results = []
        i = 0
        n = len(source)
        while i < n:
            char = source[i]
            if char in ("{", "["):
                open_char = char
                close_char = "}" if char == "{" else "]"
                stack = 0
                in_string = False
                escape = False
                start_pos = i
                end_pos = -1

                for j in range(start_pos, n):
                    ch = source[j]
                    if escape:
                        escape = False
                        continue
                    if ch == "\\":
                        if in_string:
                            escape = True
                        continue
                    if ch == '"':
                        in_string = not in_string
                        continue
                    if not in_string:
                        if ch == open_char:
                            stack += 1
                        elif ch == close_char:
                            stack -= 1
                            if stack == 0:
                                end_pos = j
                                break

                if end_pos != -1:
                    candidate = source[start_pos : end_pos + 1]
                    results.append((start_pos, end_pos, candidate))
                    i = end_pos + 1
                    continue
            i += 1
        return results

    # 1. Search candidate markdown code blocks
    # Priority 1: ```json ... ``` blocks
    json_block_matches = list(re.finditer(r"```json\s*([\s\S]*?)\s*```", trimmed, re.IGNORECASE))
    for m in json_block_matches:
        candidate = m.group(1).strip()
        if _is_valid_or_plausible_json(candidate):
            return candidate
        inner_candidates = _scan_balanced_in_text(candidate)
        for _, _, inner in inner_candidates:
            if _is_valid_or_plausible_json(inner):
                return inner

    # Priority 2: Full text balanced scan BEFORE generic fences fallback!
    # Because full text scanner tracks quotes and ignores markdown fences inside string literals!
    full_text_candidates = _scan_balanced_in_text(trimmed)
    for _, _, candidate in full_text_candidates:
        if _is_valid_or_plausible_json(candidate):
            return candidate

    # Priority 3: Generic ``` ... ``` blocks
    generic_block_matches = list(re.finditer(r"```(?:[a-zA-Z0-9_-]+)?\s*([\s\S]*?)\s*```", trimmed, re.IGNORECASE))
    for m in generic_block_matches:
        candidate = m.group(1).strip()
        if _is_valid_or_plausible_json(candidate):
            return candidate
        inner_candidates = _scan_balanced_in_text(candidate)
        for _, _, inner in inner_candidates:
            if _is_valid_or_plausible_json(inner):
                return inner

    # 3. Fallback: unclosed or truncated JSON
    start_curly = trimmed.find("{")
    start_bracket = trimmed.find("[")

    if start_curly == -1 and start_bracket == -1:
        raise ValueError(f"No JSON opening bracket '{{' or '[' found in text: {text[:150]}...")

    if start_curly != -1 and (start_bracket == -1 or start_curly < start_bracket):
        start_idx = start_curly
        close_char = "}"
    else:
        start_idx = start_bracket
        close_char = "]"

    last_close = trimmed.rfind(close_char)
    if last_close > start_idx:
        return trimmed[start_idx : last_close + 1]

    raise ValueError(f"Could not extract balanced JSON from: {text[:150]}...")


def clean_json_syntax(raw_json: str) -> str:
    """Sanitize common minor JSON flaws with state-aware token scanning.

    1. Executes safe ast.literal_eval conversion on single-quoted JSON dicts/lists.
    2. Strips inline '//' and '/* ... */' comments outside string literals (tracking ' and ").
    3. Removes trailing commas before '}' or ']' outside string literals (tracking ' and ").
    4. Converts single-quoted python dict strings to valid JSON quotes if needed.
    5. Escapes raw control characters (literal newlines/tabs) inside string literals.
    """
    if not raw_json:
        return raw_json

    text = raw_json.strip()

    # Pre-step: If it starts with { or [ and looks like a single-quoted Python dict,
    # convert safely via ast.literal_eval before stripping comments or commas
    if (text.startswith("{") and text.endswith("}")) or (text.startswith("[") and text.endswith("]")):
        try:
            py_compat = re.sub(r"\btrue\b", "True", text)
            py_compat = re.sub(r"\bfalse\b", "False", py_compat)
            py_compat = re.sub(r"\bnull\b", "None", py_compat)
            evaluated = ast.literal_eval(py_compat)
            if isinstance(evaluated, (dict, list)):
                text = json.dumps(evaluated)
        except Exception:
            pass

    # Step A: Strip comments outside string literals (tracking both double and single quotes)
    out = []
    i = 0
    n = len(text)
    in_str = False
    quote_char = None
    escape = False

    while i < n:
        c = text[i]
        if escape:
            out.append(c)
            escape = False
            i += 1
            continue
        if c == "\\":
            out.append(c)
            if in_str:
                escape = True
            i += 1
            continue
        if c in ('"', "'"):
            if not in_str:
                in_str = True
                quote_char = c
            elif quote_char == c:
                in_str = False
                quote_char = None
            out.append(c)
            i += 1
            continue

        if not in_str:
            # Check for line comment //
            if c == "/" and i + 1 < n and text[i + 1] == "/":
                j = i + 2
                while j < n and text[j] != "\n":
                    j += 1
                i = j
                continue
            # Check for block comment /* ... */
            if c == "/" and i + 1 < n and text[i + 1] == "*":
                j = i + 2
                while j + 1 < n and not (text[j] == "*" and text[j + 1] == "/"):
                    j += 1
                i = j + 2
                out.append(" ")
                continue

        out.append(c)
        i += 1

    text = "".join(out)

    # Step B: Remove trailing commas before '}' or ']' outside string literals
    out = []
    i = 0
    n = len(text)
    in_str = False
    quote_char = None
    escape = False

    while i < n:
        c = text[i]
        if escape:
            out.append(c)
            escape = False
            i += 1
            continue
        if c == "\\":
            out.append(c)
            if in_str:
                escape = True
            i += 1
            continue
        if c in ('"', "'"):
            if not in_str:
                in_str = True
                quote_char = c
            elif quote_char == c:
                in_str = False
                quote_char = None
            out.append(c)
            i += 1
            continue

        if not in_str and c == ",":
            # Peek forward through whitespace and redundant commas
            j = i + 1
            while j < n and text[j] in " \t\r\n,":
                j += 1
            if j < n and text[j] in ("}", "]"):
                # Omit comma
                i += 1
                continue

        out.append(c)
        i += 1

    text = "".join(out)

    # Step C: Handle single-quoted JSON if standard parse fails
    try:
        json.loads(text)
        return text
    except Exception:
        pass

    # If starts with { or [ and contains single quotes, try ast.literal_eval safe conversion
    if (text.startswith("{") and text.endswith("}")) or (text.startswith("[") and text.endswith("]")):
        try:
            py_compat = re.sub(r"\btrue\b", "True", text)
            py_compat = re.sub(r"\bfalse\b", "False", py_compat)
            py_compat = re.sub(r"\bnull\b", "None", py_compat)
            evaluated = ast.literal_eval(py_compat)
            if isinstance(evaluated, (dict, list)):
                return json.dumps(evaluated)
        except Exception:
            pass

    # Step D: Escape unescaped literal newlines inside string literals
    out = []
    i = 0
    n = len(text)
    in_str = False
    quote_char = None
    escape = False
    while i < n:
        c = text[i]
        if escape:
            out.append(c)
            escape = False
            i += 1
            continue
        if c == "\\":
            out.append(c)
            if in_str:
                escape = True
            i += 1
            continue
        if c in ('"', "'"):
            if not in_str:
                in_str = True
                quote_char = c
            elif quote_char == c:
                in_str = False
                quote_char = None
            out.append(c)
            i += 1
            continue
        if in_str and c == "\n":
            out.append("\\n")
            i += 1
            continue
        if in_str and c == "\r":
            out.append("\\r")
            i += 1
            continue
        if in_str and c == "\t":
            out.append("\\t")
            i += 1
            continue
        out.append(c)
        i += 1

    return "".join(out)


def parse_and_validate(raw_text: str, schema: Type[T]) -> Tuple[Optional[T], Optional[str]]:
    """Attempt to extract, clean, and validate JSON against a Pydantic schema.

    Returns:
        (model_instance, error_message): Exactly one will be non-None.
    """
    try:
        json_str = extract_json_substring(raw_text)
    except ValueError as e:
        return None, f"JSON Extraction Error: {str(e)}"

    cleaned = clean_json_syntax(json_str)

    try:
        instance = schema.model_validate_json(cleaned)
        return instance, None
    except ValidationError as ve:
        error_details = []
        for err in ve.errors():
            loc = ".".join(str(x) for x in err.get("loc", []))
            msg = err.get("msg", "")
            error_details.append(f"Field '{loc}': {msg}")
        return None, "Schema Validation Error:\n" + "\n".join(error_details)
    except (ValueError, json.JSONDecodeError) as e:
        try:
            py_compat = re.sub(r"\btrue\b", "True", cleaned)
            py_compat = re.sub(r"\bfalse\b", "False", py_compat)
            py_compat = re.sub(r"\bnull\b", "None", py_compat)
            py_obj = ast.literal_eval(py_compat)
            if isinstance(py_obj, (dict, list)):
                return schema.model_validate(py_obj), None
        except Exception:
            pass
        return None, f"JSON Syntax Error: {str(e)}"
    except Exception as e:
        return None, f"Unexpected Validation Error: {str(e)}"


def build_reflection_prompt(previous_output: str, error_msg: str, schema: Type[BaseModel]) -> str:
    """Generate a high-efficacy correction prompt for self-healing schema retries."""
    schema_json = json.dumps(schema.model_json_schema(), indent=2)
    truncated_prev = previous_output[:600] + ("..." if len(previous_output) > 600 else "")
    return (
        f"Your previous response failed validation with the following error:\n"
        f"--- ERROR ---\n{error_msg}\n\n"
        f"--- YOUR PREVIOUS OUTPUT (EXCERPT) ---\n{truncated_prev}\n\n"
        f"Please correct the output. You MUST return ONLY a valid JSON object matching this schema:\n"
        f"```json\n{schema_json}\n```\n"
        f"Do NOT include any conversational text, explanatory commentary, or markdown outside the JSON."
    )
