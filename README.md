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

## What it flags

rein judges the content of the action. It returns `HIGH` for, among others:

- unsafe code execution: `os.system`, `subprocess` with `shell=True`, `eval`, `exec`
- unsafe deserialization and loaders: `pickle.loads`, `yaml.load`, `marshal.loads`
- hard-coded credentials: AWS, Stripe, GitLab, SendGrid, npm and similar keys
- weakened security: disabled TLS verification, weak hashes (md5/sha1)

The exact rule set is rein's, so it grows with the engine. Lower-severity
findings (lint, style, slop) map to `MEDIUM`/`LOW`.

## Fail closed on unparseable code

If a `.py` action cannot be parsed, rein's AST-based security checks cannot run,
so the code is unanalyzed rather than safe. In that case the analyzer returns
`HIGH` instead of letting the result downgrade to the syntax error's own level.
"Cannot analyze this code" must not read as "this code is safe." The rule is
scoped to `.py`, so a non-Python command or a text file is left to its normal
verdict.

## Use alongside other analyzers

This is the code-content layer. It does not authorize actions or inspect shell
command patterns. Run it together with OpenHands' action and shell-pattern checks
for defense in depth; rein answers "is the code being written dangerous," the
others answer "is this action allowed to run."

## Configure with .rein.toml

The decision rules are data, not a Python class. rein reads a `.rein.toml` at the
project root for the verdict policy (`fail_at`, per-category thresholds), rule
disables, and custom regex rules, so a maintainer can declare what is blocked
without changing this analyzer. See the rein docs for the format.

## License

Apache-2.0. See `LICENSE`.
