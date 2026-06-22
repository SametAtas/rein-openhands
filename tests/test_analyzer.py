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


def test_unparseable_python_fails_closed_high():
    # An unparseable .py means rein's AST security checks did not run, so a
    # dangerous call could slip through. Must be HIGH, not the syntax error's MEDIUM.
    risk = ReinSecurityAnalyzer().security_risk(
        _event("app.py", "import os\nos.system(cmd\n")  # missing paren
    )
    assert risk == SecurityRisk.HIGH


def test_non_python_unparseable_not_forced_high():
    # A non-.py action is left to its normal verdict (and the shell analyzer);
    # fail-closed is scoped to Python so commands are not blanket-flagged.
    risk = ReinSecurityAnalyzer().security_risk(
        _event("notes.md", "this is (not python and that is fine\n")
    )
    assert risk == SecurityRisk.LOW


class _Command(Action):
    command: str


def _command_event(command: str) -> ActionEvent:
    return ActionEvent(
        thought=[TextContent(text="running a command")],
        action=_Command(command=command),
        tool_name="execute_bash",
        tool_call_id="call_1",
        tool_call=MessageToolCall(
            id="call_1", name="execute_bash", arguments="{}", origin="completion"
        ),
        llm_response_id="resp_1",
    )


def test_shell_command_is_low_not_medium():
    # A command (no path) is not Python; the failed Python parse must not leak as
    # MEDIUM. rein defers to the shell analyzer here.
    risk = ReinSecurityAnalyzer().security_risk(_command_event("rm -rf /"))
    assert risk == SecurityRisk.LOW


def test_secret_in_command_is_high():
    # Secrets are regex-based, so they fire on a command regardless of parsing.
    risk = ReinSecurityAnalyzer().security_risk(
        _command_event('export KEY="AKIAIOSFODNN7EXAMPLE"')
    )
    assert risk == SecurityRisk.HIGH


class _Patch(Action):
    patch: str


class _Edit(Action):
    new_string: str


class _Script(Action):
    script: str


def _action_event(action: Action, tool_name: str) -> ActionEvent:
    return ActionEvent(
        thought=[TextContent(text="x")],
        action=action,
        tool_name=tool_name,
        tool_call_id="call_1",
        tool_call=MessageToolCall(
            id="call_1", name=tool_name, arguments="{}", origin="completion"
        ),
        llm_response_id="resp_1",
    )


_DANGER = "import os\nos.system(cmd)\n"


def test_patch_field_is_reviewed_high():
    # An ApplyPatchAction carries a diff, not source. rein must review the added
    # lines (else os.system in a patch is missed). Regression for issue #1.
    diff = "--- a/app.py\n+++ b/app.py\n@@ -1 +1,3 @@\n x = 1\n+import os\n+os.system(cmd)\n"
    risk = ReinSecurityAnalyzer().security_risk(_action_event(_Patch(patch=diff), "apply_patch"))
    assert risk == SecurityRisk.HIGH


def test_indented_patch_is_reviewed_high():
    # Added lines inside a function are indented; they must be dedented so they
    # still parse as Python and the danger is caught.
    diff = (
        "--- a/app.py\n+++ b/app.py\n@@ -1,2 +1,4 @@\n"
        " def run():\n     pass\n+    import os\n+    os.system(cmd)\n"
    )
    risk = ReinSecurityAnalyzer().security_risk(_action_event(_Patch(patch=diff), "apply_patch"))
    assert risk == SecurityRisk.HIGH


def test_benign_patch_is_low():
    diff = "--- a/app.py\n+++ b/app.py\n@@ -1 +1,2 @@\n x = 1\n+y = 2\n"
    risk = ReinSecurityAnalyzer().security_risk(_action_event(_Patch(patch=diff), "apply_patch"))
    assert risk == SecurityRisk.LOW


def test_new_string_field_is_reviewed_high():
    # str-replace / Gemini edits put the new source in new_string. Issue #1.
    risk = ReinSecurityAnalyzer().security_risk(_action_event(_Edit(new_string=_DANGER), "str_replace"))
    assert risk == SecurityRisk.HIGH


def test_script_field_is_reviewed_high():
    # The workflow runner puts source in script. Issue #1.
    risk = ReinSecurityAnalyzer().security_risk(_action_event(_Script(script=_DANGER), "run_workflow"))
    assert risk == SecurityRisk.HIGH


def test_works_inside_ensemble():
    from openhands.sdk.security.defense_in_depth import PatternSecurityAnalyzer
    from openhands.sdk.security.ensemble import EnsembleSecurityAnalyzer

    ensemble = EnsembleSecurityAnalyzer(
        analyzers=[ReinSecurityAnalyzer(), PatternSecurityAnalyzer()]
    )
    risk = ensemble.security_risk(_event("app.py", "import os\nos.system(cmd)\n"))
    assert risk == SecurityRisk.HIGH
