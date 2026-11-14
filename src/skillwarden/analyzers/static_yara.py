"""YARA signature matching. Catches known-bad byte/text patterns (webshells,
download-cradles, embedded executables, obfuscated pickle) that are awkward to
express as line regexes.

yara-python is an optional dependency (`pip install skillwarden[yara]`). When it
is absent the analyzer skips cleanly — it never blocks a scan.
"""

from __future__ import annotations

from skillwarden.analyzers.base import Analyzer, ScanContext
from skillwarden.models import Category, Finding, Severity, Source

# Bundled baseline rules. Extend with team-specific signatures over time.
_RULES_SOURCE = r"""
rule Download_Cradle {
    meta: severity = "high"
         desc = "Remote download-and-execute cradle"
    strings:
        $ps  = "IEX(New-Object Net.WebClient).DownloadString" nocase
        $ps2 = "Invoke-Expression (New-Object Net.WebClient)" nocase
        $sh  = /curl\s+[^\n|]+\|\s*(ba)?sh/ nocase
    condition: any of them
}
rule Webshell_Eval {
    meta: severity = "critical"
         desc = "Webshell-style eval of request data"
    strings:
        $a = /eval\s*\(\s*\$_(POST|GET|REQUEST)/ nocase
        $b = /system\s*\(\s*\$_(POST|GET|REQUEST)/ nocase
        $c = "exec($_" nocase
    condition: any of them
}
rule Embedded_Executable {
    meta: severity = "high"
         desc = "Embedded Windows PE executable"
    strings:
        $mz = "This program cannot be run in DOS mode"
    condition: $mz
}
rule Obfuscated_Pickle {
    meta: severity = "high"
         desc = "Base64-wrapped pickle deserialization"
    strings:
        $a = /base64\.b64decode\([^)]+\)/
        $b = "pickle.loads"
    condition: all of them
}
"""


class YaraAnalyzer(Analyzer):
    id = "static_yara"
    category = Category.DANGEROUS_CODE  # YARA hits roll up under dangerous code

    def __init__(self) -> None:
        self._rules = None
        self._available = self._compile()

    def _compile(self) -> bool:
        try:
            import yara  # optional dependency
        except ImportError:
            return False
        try:
            self._rules = yara.compile(source=_RULES_SOURCE)
            return True
        except Exception:
            return False

    def run(self, ctx: ScanContext) -> list[Finding]:
        if not self._available or self._rules is None:
            return []
        out: list[Finding] = []
        for path, text in ctx.file_cache.items():
            for match in self._rules.match(data=text.encode("utf-8", "ignore")):
                meta = match.meta
                sev = _SEVERITY.get(str(meta.get("severity", "medium")), Severity.MEDIUM)
                out.append(
                    Finding(
                        rule_id=f"YARA-{match.rule}",
                        category=self.category,
                        severity=sev,
                        title=f"YARA signature: {match.rule}",
                        description=str(meta.get("desc", f"Matched YARA rule {match.rule}.")),
                        source=Source.STATIC,
                        confidence=0.85,
                        file=path,
                    )
                )
        return out


_SEVERITY = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
}
