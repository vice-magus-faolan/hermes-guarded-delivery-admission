# Hermes Guarded Delivery Admission

A dependency-free native Hermes plugin for **read-only live Kanban worker
admission**. It exposes one tool, `guarded_delivery_admission`, and changes no
Hermes core code.

**Status:** extracted implementation for review. Publication is not activation.
Plugin ID: `guarded-delivery-admission`. Repository: `hermes-guarded-delivery-admission`.

## What it does—and does not do

A `preflight` call checks an operator-selected, SHA-256-pinned policy against:

- the exact native source files and running interpreter;
- native execution context and the caller's own worker markers;
- the current task/run, profile, claim, lease, PID and process fingerprint;
- read-only SQLite records and exact artifact hashes;
- a second ownership/record observation after artifact I/O.

Callers cannot provide task, board, repository, command, policy path, or digest
selectors. The tool accepts only `{"phase": "preflight"}` for successful admission.
It never imports artifact helpers, spawns a subprocess, connects to a transport,
writes the board, moves Git refs, or runs delivery commands.

Even a successful response keeps **`workflow_ready: false` and `effects: false`**.
It is a point-in-time check, not a transferable capability, approval receipt,
lease renewal, review verdict, or proof of product delivery. The four other phase
names in the schema are reserved; they always refuse execution, including after
synthetic admission. An `ssh` policy describes a contract; it does not enable SSH.

This is deliberately **not a complete guarded-delivery adapter**. Extraction
neither advances held delivery work nor changes its review/publication gates.

## Responses and failure boundaries

The response is JSON with `ok`, `admitted`, `workflow_ready` and `effects`.
A successful preflight also includes its phase, policy digest and identity:
task, board, profile, run, PID and fingerprint. Claim-lock values are never
returned. A refusal includes a machine-readable `reason` without file contents.

Ordinary callers with no native owned task refuse `worker_identity_missing`;
explicit non-dispatcher/delegated contexts refuse `not_dispatcher_owned`.
Native context eligibility alone does not establish task ownership. Malformed,
stale, mismatched, linked or unavailable authority fails closed. Changing captured
plugin policy settings invalidates that registration (`configuration_changed`).

No refusal should be "fixed" by fabricating worker markers, loosening policy,
clearing delegation/security markers, or calling from a privileged wrapper.

## Policy and configuration

Policy is **operator-owned private state**, not repository content. Its version-1
shape is separate from any workspace delivery-policy format. See
[`examples/policy.example.json`](examples/policy.example.json) for an inert
illustration; placeholder pins intentionally make it unusable until reviewed
real values are supplied. Do not publish a filled production policy.

Policy permits only `permissions: ["preflight"]` and requires an empty
`delivery_contract.executables` list. The contract's candidate and old commit
SHAs are required metadata: this plugin does not inspect Git, verify review, or
check that the target ref still has those commits.

Use profile-local plugin settings:

```yaml
plugins:
  # Add to the existing enabled list; do not replace other selections.
  enabled:
    - guarded-delivery-admission
  entries:
    guarded-delivery-admission:
      allow_tool_override: false
      settings:
        policy_path: /absolute/private/policy.local.json
        policy_sha256: <64-lowercase-hex-digest-of-exact-policy-bytes>
```

Use native configuration controls to apply settings deliberately. Workers must
also select the `guarded-delivery-admission` toolset in their intended CLI tool
scope; enablement alone does not prove model-facing exposure. A changed runtime,
interpreter, policy, artifact, task or worker can require a newly reviewed policy.
The plugin will not regenerate one for you.

The runtime uses Linux `/proc/self/exe` and native process fingerprints. Policy,
interpreter, pinned native/artifact files and board paths must be absolute with
no linked parent or leaf. If plugin installation uses a repository link, pin the
resolved physical artifact paths—not the linked plugin path. Install only trusted
native code; this plugin is not a sandbox against malicious in-process code.

## Installation and rollback

After independent review, human approval and **separate deployment approval**:

```sh
hermes -p <profile> plugins install vice-magus-faolan/hermes-guarded-delivery-admission --ref <full-reviewed-sha> --no-enable
hermes -p <profile> plugins doctor guarded-delivery-admission --ci
# Configure the private policy and intended worker toolset separately.
hermes -p <profile> plugins enable guarded-delivery-admission --no-allow-tool-override
```

The native runtime bundle is at repository root: `plugin.yaml` and `__init__.py`.
A deliberately reviewed repo-linked installation is also possible using native
directory discovery; it must not point at a writable feature worktree. Source
updates of a linked checkout are runtime promotions and need their own gate.
Do not pip-edit a live Hermes dependency generation for this stdlib-only plugin.

Already-running workers are not patched retroactively. Verify the intended
profile's fresh native registration, actual worker tool exposure and an
explicitly authorized no-effect probe. Plugin Doctor alone proves registration,
not genuine worker admission or installation readiness. Do not restart unrelated
services as part of installation. Roll back using native disable and the retained
previous source/configuration:

```sh
hermes -p <profile> plugins disable guarded-delivery-admission
```

## Reproducible verification

The exercised baseline is Python 3.14/Linux and clean NousResearch/hermes-agent
commit `f42f579cf8bac4918ac9599bece71618afadd846`.

```sh
git clone https://github.com/NousResearch/hermes-agent.git .hermes-runtime-source
git -C .hermes-runtime-source checkout --detach f42f579cf8bac4918ac9599bece71618afadd846
python3 -m venv .venv-test
.venv-test/bin/python -I -m pip install -r requirements-test.txt
export HERMES_AGENT_ROOT="$PWD/.hermes-runtime-source"
.venv-test/bin/python -I scripts/verify.py
.venv-test/bin/python -I -O scripts/verify.py
```

The verifier requires the exact clean native source (including no untracked
importable files), discovers all tests, refuses failures/skips, and invokes the
real native Doctor handler on an exact two-file runtime bundle. Test/Doctor
scratch homes do not touch live boards or policies, and the source-only verifier
does not launch installation bootstrap or dependency repair.

Tests preserve inherited admission boundary coverage and add portable native
loader/context/transport refusals plus verifier regressions. Positive admission
uses a **FakeRuntime and synthetic SQLite fixture**, not forged process markers.
Native loader tests exercise actual registration and ordinary/delegated context
refusals with generated disposable policies pinned to the selected native source.
These checks do **not** prove a new dispatcher-owned positive deployment,
Git/review authorization or end-to-end delivery. CI runs normal and optimized
verification against the same pinned source.

See [provenance](docs/provenance.md), [security](SECURITY.md) and
[contributing](CONTRIBUTING.md).

## License

SPDX-License-Identifier: **GPL-3.0-or-later**. See [LICENSE](LICENSE).
