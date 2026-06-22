"""Defense in depth: rein's code-content analyzer plus the shell-pattern analyzer.

`EnsembleSecurityAnalyzer` runs both child analyzers and takes the worst-case
risk. The two cover different things and miss different things, so together they
cover more than either alone:

- `ReinSecurityAnalyzer` judges the CODE an action writes (os.system, eval,
  pickle, hard-coded secrets, and so on), deterministically and with no LLM.
- `PatternSecurityAnalyzer` judges shell and command patterns on the action.

Set the ensemble as the conversation or agent analyzer and you get both.

Run it (needs the package, which pulls openhands-sdk and rein-engine):

    pip install rein-openhands
    python examples/ensemble.py
"""

from __future__ import annotations

from openhands.sdk.event.llm_convertible import ActionEvent
from openhands.sdk.llm.message import MessageToolCall, TextContent
from openhands.sdk.security.defense_in_depth import PatternSecurityAnalyzer
from openhands.sdk.security.ensemble import EnsembleSecurityAnalyzer
from openhands.sdk.tool.schema import Action

from rein_openhands import ReinSecurityAnalyzer


def build_analyzer() -> EnsembleSecurityAnalyzer:
    """The defense-in-depth setup. Set it on the conversation, with a policy:

        conversation.set_security_analyzer(build_analyzer())
        conversation.set_confirmation_policy(ConfirmRisky(threshold=SecurityRisk.HIGH))
    """
    return EnsembleSecurityAnalyzer(
        analyzers=[ReinSecurityAnalyzer(), PatternSecurityAnalyzer()]
    )


class _WriteFile(Action):
    path: str
    content: str


def _event(path: str, content: str) -> ActionEvent:
    return ActionEvent(
        thought=[TextContent(text="writing a file")],
        action=_WriteFile(path=path, content=content),
        tool_name="write_file",
        tool_call_id="c",
        tool_call=MessageToolCall(
            id="c", name="write_file", arguments="{}", origin="completion"
        ),
        llm_response_id="r",
    )


def main() -> int:
    ensemble = build_analyzer()
    rein = ReinSecurityAnalyzer()
    pattern = PatternSecurityAnalyzer()

    dangerous = _event("app.py", "import os\nos.system(cmd)\n")
    clean = _event("app.py", "def add(a, b):\n    return a + b\n")

    for label, action in [("dangerous .py (os.system)", dangerous), ("clean .py", clean)]:
        print(
            f"{label}: rein={rein.security_risk(action).value} "
            f"pattern={pattern.security_risk(action).value} "
            f"ensemble={ensemble.security_risk(action).value}"
        )

    print(
        "\nrein catches the code-content risk the shell-pattern layer alone "
        "misses; the ensemble returns the worst case."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
