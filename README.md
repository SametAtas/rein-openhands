# rein-openhands

A deterministic, no-LLM `SecurityAnalyzer` for [OpenHands](https://github.com/OpenHands/software-agent-sdk), backed by the [rein](https://github.com/SametAtas/rein) engine.

OpenHands' built-in `LLMSecurityAnalyzer` asks the model to grade its own
actions. This grades them with rein instead. Before an action runs, rein reviews
the code or command it would write for leaked secrets, unsafe code, and slop, and
returns a `SecurityRisk` that feeds OpenHands' `ConfirmRisky` policy. No model in
the loop, so the same action gets the same verdict every time.

## Install

```bash
pip install rein-openhands
```

It pulls in `rein-engine` and `openhands-sdk`.

## Use

```python
from rein_openhands import ReinSecurityAnalyzer

agent = Agent(llm=llm, tools=tools, security_analyzer=ReinSecurityAnalyzer())
```

Or set it on an existing conversation:

```python
conversation.set_security_analyzer(ReinSecurityAnalyzer())
```

That is all. See the OpenHands docs for agent and confirmation-policy setup.

## What it judges

rein judges the content of the action: secrets, unsafe code patterns, and slop in
the code being written. It is not a shell allow or deny list, OpenHands' own
action checks and confirmation policy stay in charge of pure action
authorization. rein is the deterministic code-content layer alongside them, and
is strongest when the action writes a code file.

## License

Apache-2.0. See `LICENSE`.
