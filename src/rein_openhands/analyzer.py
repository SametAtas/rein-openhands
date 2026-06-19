"""A deterministic OpenHands SecurityAnalyzer backed by the rein engine.

OpenHands' built-in LLMSecurityAnalyzer asks the model to grade its own actions.
This grades them with rein instead: it reviews the code or command an action
would run and returns a SecurityRisk, with no LLM and the same verdict every
time. The risk feeds OpenHands' ConfirmRisky policy to block or confirm before
execution.
"""

from __future__ import annotations

from openhands.sdk.event.llm_convertible import ActionEvent
from openhands.sdk.security.analyzer import SecurityAnalyzerBase
from openhands.sdk.security.risk import SecurityRisk

from rein.core.code import code_domain
from rein.core.findings import Finding, Severity

# Fields, in priority order, that carry the code or command an action will run.
_CONTENT_KEYS = ("content", "code", "command", "new_str", "file_text", "text")
# Fields that carry a path, so rein gates the right (e.g. Python) checks.
_PATH_KEYS = ("path", "file_path", "file", "filename")


def _extract(action: ActionEvent) -> tuple[str, str | None]:
    """Pull the reviewable content and a path hint out of an action's payload."""
    payload = action.action.model_dump() if action.action else {}
    path = next((str(payload[k]) for k in _PATH_KEYS if payload.get(k)), None)
    parts = [str(payload[k]) for k in _CONTENT_KEYS if payload.get(k)]
    # Fall back to the whole payload so a secret anywhere is still scanned.
    content = "\n".join(parts) if parts else str(payload)
    return content, path


def _to_risk(findings: list[Finding]) -> SecurityRisk:
    """Map rein's worst finding severity onto OpenHands' SecurityRisk."""
    worst = max((f.severity for f in findings), default=Severity.INFO)
    if worst >= Severity.HIGH:        # HIGH or CRITICAL
        return SecurityRisk.HIGH
    if worst == Severity.MEDIUM:
        return SecurityRisk.MEDIUM
    return SecurityRisk.LOW           # INFO/LOW or nothing found


class ReinSecurityAnalyzer(SecurityAnalyzerBase):
    """Deterministic SecurityAnalyzer backed by rein (no LLM)."""

    def security_risk(self, action: ActionEvent) -> SecurityRisk:
        content, path = _extract(action)
        findings = code_domain(content, path)
        if any(f.rule_id == "lint.syntax-error" for f in findings):
            # A .py that will not parse is real code rein could not analyze, so
            # fail closed (HIGH): unanalyzed is not safe. For anything else (no
            # path, or a non-.py path) the parse failure just means the content
            # is not Python, e.g. a shell command, so the syntax error carries no
            # security signal. Drop it rather than read it as MEDIUM; the shell
            # pattern analyzer is what covers commands.
            if path is not None and path.endswith(".py"):
                return SecurityRisk.HIGH
            findings = [f for f in findings if f.rule_id != "lint.syntax-error"]
        return _to_risk(findings)
