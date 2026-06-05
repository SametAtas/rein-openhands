"""Tests for ReinSecurityAnalyzer against the real OpenHands SDK."""

from __future__ import annotations

from openhands.sdk.event.llm_convertible import ActionEvent
from openhands.sdk.llm.message import MessageToolCall, TextContent
from openhands.sdk.security.analyzer import SecurityAnalyzerBase
from openhands.sdk.security.risk import SecurityRisk
from openhands.sdk.tool.schema import Action

from rein_openhands import ReinSecurityAnalyzer


class _WriteFileAction(Action):
    path: str
    content: str


def _event(path: str, content: str) -> ActionEvent:
    return ActionEvent(
        thought=[TextContent(text="writing a file")],
        action=_WriteFileAction(path=path, content=content),
        tool_name="write_file",
        tool_call_id="call_1",
        tool_call=MessageToolCall(
            id="call_1", name="write_file", arguments="{}", origin="completion"
        ),
        llm_response_id="resp_1",
    )


def test_is_real_subclass():
    assert isinstance(ReinSecurityAnalyzer(), SecurityAnalyzerBase)


def test_unsafe_call_is_high():
    risk = ReinSecurityAnalyzer().security_risk(
        _event("app.py", "import os\nos.system(cmd)\n")
    )
    assert risk == SecurityRisk.HIGH


def test_hardcoded_secret_is_high():
    risk = ReinSecurityAnalyzer().security_risk(
        _event("config.py", 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    )
    assert risk == SecurityRisk.HIGH


def test_clean_code_is_low():
    risk = ReinSecurityAnalyzer().security_risk(
        _event("app.py", "def add(a, b):\n    return a + b\n")
    )
    assert risk == SecurityRisk.LOW


def test_deterministic():
    analyzer = ReinSecurityAnalyzer()
    event = _event("app.py", "import os\nos.system(cmd)\n")
    results = {analyzer.security_risk(event) for _ in range(20)}
    assert results == {SecurityRisk.HIGH}
