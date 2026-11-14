"""Analyzer registry.

Register every analyzer here. The engine fans these out concurrently. Adding a
category to SkillWarden = drop a module beside this one and add it to ANALYZERS.

Coverage (17 categories + YARA signatures + OSV live CVE lookups):
  static pattern : prompt injection, data exfiltration, supply chain, privilege
                   escalation, excessive agency, output handling, system prompt
                   leakage, memory poisoning, tool misuse, rogue agent,
                   anti-refusal, trigger abuse, harmful content
  AST / dataflow : dangerous code (AST), taint tracking
  structured     : MCP least privilege, MCP tool poisoning
  signatures     : YARA (optional dep)
  live           : OSV vulnerability lookups
"""

from __future__ import annotations

from skillwarden.analyzers.anti_refusal import AntiRefusalAnalyzer
from skillwarden.analyzers.base import Analyzer
from skillwarden.analyzers.dangerous_code import DangerousCodeAnalyzer
from skillwarden.analyzers.data_exfiltration import DataExfiltrationAnalyzer
from skillwarden.analyzers.excessive_agency import ExcessiveAgencyAnalyzer
from skillwarden.analyzers.harmful_content import HarmfulContentAnalyzer
from skillwarden.analyzers.mcp_least_privilege import McpLeastPrivilegeAnalyzer
from skillwarden.analyzers.mcp_tool_poisoning import McpToolPoisoningAnalyzer
from skillwarden.analyzers.memory_poisoning import MemoryPoisoningAnalyzer
from skillwarden.analyzers.osv_client import OsvAnalyzer
from skillwarden.analyzers.output_handling import OutputHandlingAnalyzer
from skillwarden.analyzers.privilege_escalation import PrivilegeEscalationAnalyzer
from skillwarden.analyzers.prompt_injection import PromptInjectionAnalyzer
from skillwarden.analyzers.rogue_agent import RogueAgentAnalyzer
from skillwarden.analyzers.static_yara import YaraAnalyzer
from skillwarden.analyzers.supply_chain import SupplyChainAnalyzer
from skillwarden.analyzers.system_prompt_leakage import SystemPromptLeakageAnalyzer
from skillwarden.analyzers.taint import TaintAnalyzer
from skillwarden.analyzers.tool_misuse import ToolMisuseAnalyzer
from skillwarden.analyzers.trigger_abuse import TriggerAbuseAnalyzer

ANALYZERS: list[Analyzer] = [
    # static pattern analyzers
    PromptInjectionAnalyzer(),
    DataExfiltrationAnalyzer(),
    SupplyChainAnalyzer(),
    PrivilegeEscalationAnalyzer(),
    ExcessiveAgencyAnalyzer(),
    OutputHandlingAnalyzer(),
    SystemPromptLeakageAnalyzer(),
    MemoryPoisoningAnalyzer(),
    ToolMisuseAnalyzer(),
    RogueAgentAnalyzer(),
    AntiRefusalAnalyzer(),
    TriggerAbuseAnalyzer(),
    HarmfulContentAnalyzer(),
    # AST / dataflow
    DangerousCodeAnalyzer(),
    TaintAnalyzer(),
    # structured config (MCP)
    McpLeastPrivilegeAnalyzer(),
    McpToolPoisoningAnalyzer(),
    # signatures + live data
    YaraAnalyzer(),
    OsvAnalyzer(),
]

__all__ = ["ANALYZERS", "Analyzer"]
