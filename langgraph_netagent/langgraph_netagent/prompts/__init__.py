"""System prompts for LangGraph NetAgent LLM nodes."""

from langgraph_netagent.prompts.fixer_prompts import FAULT_FIXER_SYSTEM_PROMPT
from langgraph_netagent.prompts.intent_prompts import INTENT_PARSER_SYSTEM_PROMPT
from langgraph_netagent.prompts.topology_prompts import TOPOLOGY_GENERATOR_SYSTEM_PROMPT
from langgraph_netagent.prompts.validation_prompts import SYNTAX_VALIDATOR_SYSTEM_PROMPT

__all__ = [
    "INTENT_PARSER_SYSTEM_PROMPT",
    "TOPOLOGY_GENERATOR_SYSTEM_PROMPT",
    "SYNTAX_VALIDATOR_SYSTEM_PROMPT",
    "FAULT_FIXER_SYSTEM_PROMPT",
]
