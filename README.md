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

Security analyzers are configured on the conversation, with a confirmation policy:

```python
from openhands.sdk import Conversation
from openhands.sdk.security import ConfirmRisky, SecurityRisk

from rein_openhands import ReinSecurityAnalyzer

conversation = Conversation(agent=agent, workspace=".")
conversation.set_security_analyzer(ReinSecurityAnalyzer())
conversation.set_confirmation_policy(ConfirmRisky(threshold=SecurityRisk.HIGH))
```

That is all. See the OpenHands docs for agent and conversation setup.

## What it flags

rein judges the content of the action. It returns `HIGH` for, among others:

- unsafe code execution: `os.system`, `subprocess` with `shell=True`, `eval`, `exec`
- unsafe deserialization and loaders: `pickle.loads`, `yaml.load`, `marshal.loads`
- unverified TLS context: `ssl._create_unverified_context`
- hard-coded credentials: AWS, Stripe, GitLab, SendGrid, npm and similar keys

Some weaker risks map to `MEDIUM`, for example weak hashes (`md5`/`sha1`) and
`requests(..., verify=False)`. Lint, style, and slop map to `MEDIUM`/`LOW`. The
exact rule set is rein's, so it grows with the engine.

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

## Policy as data (roadmap)

The rein engine already externalizes its decision rules as data: a `.rein.toml`
declares the verdict policy (`fail_at`, per-category thresholds), rule disables,
and custom regex rules, so a maintainer can declare what is blocked without
writing code. This analyzer does not yet read that config (it maps rein's finding
severities to `SecurityRisk` directly); honoring a repo's `.rein.toml` here so the
policy governs the verdict is the next planned step. See the rein docs for the
config format.

## License

Apache-2.0. See `LICENSE`.
