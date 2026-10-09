# Contributing

Keep extraction and behavior changes separate. The initial extraction preserves
`__init__.py` and `plugin.yaml` byte-for-byte; do not add delivery execution,
private policy, product constants or workspace-specific helper dependencies.

Use focused branches and Conventional Commits. Default-branch delivery is
PR-only after the minimal repository bootstrap. Request human review from
`jabez007`; independent agent review and CI do not replace that approval. No
auto-merge, runtime promotion or service restart follows from opening a PR.

Run both documented verifier commands with a clean pinned native source. Keep
all inherited boundary tests, run full discovery with zero skips, and label
synthetic success versus genuine native authority honestly. Prefer small helpers;
complexity above 15 per function needs explicit justification or refactoring.
Preserve any refused or failed validation as evidence rather than weakening it.

Native PM install/enable and fresh model-facing exposure are separate deployment
checks. Never pip-edit a live dependency generation or clear security/delegation
markers to make fixtures pass. Local policies, boards, logs, receipts, credentials
and private workspace history do not belong in Git.
