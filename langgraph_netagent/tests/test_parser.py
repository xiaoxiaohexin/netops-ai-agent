"""Comprehensive tests for robust JSON extractor, syntax cleaner, and reflection generator."""

import pytest
from pydantic import BaseModel, Field
from langgraph_netagent.llm.parser import (
    build_reflection_prompt,
    clean_json_syntax,
    extract_json_substring,
    parse_and_validate,
)
from langgraph_netagent.models.intent import NodeIntent


class DummyNestedModel(BaseModel):
    title: str
    items: list[int]
    notes: str = Field(default="")


class TestExtractJsonSubstring:
    """Test suite for extract_json_substring."""

    def test_extract_markdown_json_block(self):
        text = "Here is the response:\n```json\n{\n  \"name\": \"pc1\",\n  \"role\": \"host\"\n}\n```\nHope this helps!"
        extracted = extract_json_substring(text)
        assert extracted == '{\n  "name": "pc1",\n  "role": "host"\n}'

    def test_extract_markdown_code_block_without_tag(self):
        text = "```\n{\"name\": \"frr1\", \"role\": \"router\"}\n```"
        extracted = extract_json_substring(text)
        assert extracted == '{"name": "frr1", "role": "router"}'

    def test_extract_bare_curly_with_conversational_text(self):
        text = "Sure! Here is the JSON: {\"name\": \"srl1\", \"role\": \"router\"} Thanks!"
        extracted = extract_json_substring(text)
        assert extracted == '{"name": "srl1", "role": "router"}'

    def test_extract_nested_braces_in_strings(self):
        text = '{"name": "pc1", "role": "host", "extra_attributes": {"formula": "a + {b} = c"}}'
        extracted = extract_json_substring(text)
        assert extracted == text

    def test_extract_escaped_quotes_in_strings(self):
        text = '{"name": "pc1", "role": "host", "extra_attributes": {"quote": "hello \\"world\\""}}'
        extracted = extract_json_substring(text)
        assert extracted == text

    def test_extract_json_array(self):
        text = "List of nodes: [\"pc1\", \"pc2\", \"frr1\"] end of list"
        extracted = extract_json_substring(text)
        assert extracted == '["pc1", "pc2", "frr1"]'

    def test_extract_empty_string_raises(self):
        with pytest.raises(ValueError) as exc:
            extract_json_substring("   ")
        assert "empty" in str(exc.value)

    def test_extract_no_brackets_raises(self):
        with pytest.raises(ValueError) as exc:
            extract_json_substring("Hello, I am a network assistant without any json.")
        assert "No JSON opening bracket" in str(exc.value)


class TestCleanJsonSyntax:
    """Test suite for clean_json_syntax."""

    def test_clean_trailing_comma_object(self):
        raw = '{"name": "pc1", "role": "host",}'
        cleaned = clean_json_syntax(raw)
        assert cleaned == '{"name": "pc1", "role": "host"}'

    def test_clean_trailing_comma_array(self):
        raw = '{"nodes": ["pc1", "pc2", "frr1",]}'
        cleaned = clean_json_syntax(raw)
        assert cleaned == '{"nodes": ["pc1", "pc2", "frr1"]}'

    def test_clean_nested_trailing_commas_multiline(self):
        raw = """{
            "title": "demo",
            "items": [
                1,
                2,
            ],
            "notes": "ok",
        }"""
        cleaned = clean_json_syntax(raw)
        assert ",]" not in cleaned.replace(" ", "").replace("\n", "")
        assert ",}" not in cleaned.replace(" ", "").replace("\n", "")


class TestParseAndValidate:
    """Test suite for parse_and_validate."""

    def test_parse_and_validate_success(self):
        text = "```json\n{\"name\": \"pc1\", \"role\": \"host\", \"subnets\": [\"10.1.1.0/24\",]}\n```"
        instance, err = parse_and_validate(text, NodeIntent)
        assert err is None
        assert instance is not None
        assert instance.name == "pc1"
        assert instance.role == "host"
        assert instance.subnets == ["10.1.1.0/24"]

    def test_parse_and_validate_syntax_error(self):
        text = '{"name": "pc1", "role": "host", "subnets": [broken'
        instance, err = parse_and_validate(text, NodeIntent)
        assert instance is None
        assert err is not None
        assert "JSON" in err or "Syntax" in err

    def test_parse_and_validate_schema_validation_error(self):
        # Missing required field 'role'
        text = '{"name": "pc1"}'
        instance, err = parse_and_validate(text, NodeIntent)
        assert instance is None
        assert err is not None
        assert "Schema Validation Error" in err
        assert "role" in err


class TestBuildReflectionPrompt:
    """Test suite for build_reflection_prompt."""

    def test_build_reflection_prompt_content(self):
        err_msg = "Field 'role': Field required"
        prev_output = '{"name": "pc1"}'
        prompt = build_reflection_prompt(prev_output, err_msg, NodeIntent)

        assert "--- ERROR ---" in prompt
        assert err_msg in prompt
        assert "--- YOUR PREVIOUS OUTPUT (EXCERPT) ---" in prompt
        assert prev_output in prompt
        assert '"properties":' in prompt  # JSON schema check
        assert '"role":' in prompt
