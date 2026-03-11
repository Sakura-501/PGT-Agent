"""
Brain module for PGT-Agent.

This module contains the core reasoning components:
- prompts: System prompts and prompt builders
- validator: Report quality validation
- reflector: Critic reflection for iterative improvement
"""

from pgt_agent.brain.prompts import (
    CRITIC_SYSTEM_PROMPT,
    PGT_REPORT_SCHEMA,
    REACT_SYSTEM_PROMPT,
    build_reflection_prompt,
    build_user_prompt,
)
from pgt_agent.brain.reflector import (
    extract_json,
    reflect_critic,
    reflect_with_rules,
    should_continue_iteration,
)
from pgt_agent.brain.validator import validate_report

__all__ = [
    # Prompts
    "REACT_SYSTEM_PROMPT",
    "CRITIC_SYSTEM_PROMPT",
    "PGT_REPORT_SCHEMA",
    "build_user_prompt",
    "build_reflection_prompt",
    # Validator
    "validate_report",
    # Reflector
    "extract_json",
    "reflect_critic",
    "reflect_with_rules",
    "should_continue_iteration",
]
