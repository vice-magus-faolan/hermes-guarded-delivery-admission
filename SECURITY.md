# Security and trust boundary

This plugin is a read-only admission check, not delivery authority. `ok: true`
never means `workflow_ready: true` or permission to execute any phase. Policy
contract fields do not establish Git state, review approval or publication rights.

Native plugin code executes inside Hermes. Install trusted, independently
reviewed immutable source only; it cannot sandbox malicious same-process code or
defeat an administrator who can rewrite runtime, interpreter, policy or board.
File hashes and repeated observations detect selected drift, not an atomic lock
against arbitrary concurrent mutation. The final observation can become stale
immediately. Never reuse a preflight result as a later-operation capability.

Policy and artifact files are read locally, and may be large; operator-selected
paths and runtime protections must bound that exposure. Symlink checks and
O_NOFOLLOW at the leaf do not establish a race-free open of every parent.
SQLite is opened read-only/query-only; no migration, lease renewal or lifecycle
write is attempted. Claim-lock values stay internal. Returned task/run/process
identities can still be sensitive: keep receipts and production policies private.

Four reserved phase names remain unavailable. Do not extend this boundary via
shell commands, helper imports, reconstructed worker markers, raw lifecycle SQL,
privilege grants or altered security/delegation markers. An execution adapter
would be a separately designed and reviewed product change, not an extraction.

Report security concerns privately to the repository owner first. Do not include
credentials, real claim locks, production policies, private topology or live board
contents in public issues. This extraction ships no production configuration and
makes no new live worker-positive or end-to-end delivery claim.
