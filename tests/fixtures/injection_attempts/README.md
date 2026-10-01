# Injection attempt corpus

Curated prompt-injection payloads used by `tests/security/test_prompt_injection.py`
to red-team the `safety/` layer.

## Files

- `promptinject_goal_hijacking.json` — goal-hijacking attacks.
- `promptinject_prompt_leaking.json` — prompt-leaking attacks.
- `positive_controls.json` — payloads the current `INJECTION_PATTERNS` are
  written to catch. These guard the harness: if they stop being detected, the
  suite is no longer reaching the real code path and every other result in it
  is meaningless.

## Provenance

The two `promptinject_*` files are copied verbatim from
[PromptInject](https://github.com/agencyenterprise/PromptInject),
`promptinject/prompt_data.py` (`goal_hikacking_attacks` and
`prompt_leaking_attacks`), with the corpus' `{REPLACE_rogue_string}` placeholder
filled by its own rogue string `"I hate humans"`. PromptInject is the code
artifact of Perez & Ribeiro, *Ignore Previous Prompt: Attack Techniques For
Language Models*, [arXiv:2211.09527](https://arxiv.org/abs/2211.09527)
(NeurIPS 2022 ML Safety Workshop).

Payloads are stored as data rather than as Python literals so the corpus can
grow without touching test code, and so each entry keeps its `source` beside
it. Provenance is what makes this corpus worth anything: a reviewer can check
every string against the upstream file.

## Schema

Each file is a JSON object:

```json
{
  "source": "<human-readable provenance for every payload in this file>",
  "source_url": "<where a reviewer can verify them>",
  "payloads": [
    {"id": "<stable id, referenced by test ids and xfail reasons>",
     "payload": "<the exact string fed to the defense>",
     "note": "<what this payload exercises>"}
  ]
}
```

`id` values are stable: `tests/security/test_prompt_injection.py` parametrises
on them, so they appear in test output and in `xfail` reasons. Renaming one
renames a test.

## Adding a payload

Add it to the file matching its provenance, or add a new file with its own
`source` and `source_url`. The suite discovers files by glob, so no test change
is needed. Record the observed behavior honestly: if the defense does not
currently catch it, it belongs in the expected-undetected set in the test
module, not asserted as blocked.
