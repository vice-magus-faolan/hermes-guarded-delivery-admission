# Extraction provenance

This repository was extracted from a retained hash-pinned admission-only source
bundle in a private operator workspace. **That source was not Git-tracked.**
There is no source commit claim, and no workspace history was imported.
The installed default and builder-profile copies matched the retained runtime
bundle byte-for-byte at extraction.

Source bundle manifest SHA-256:
`d0371290a8bd39a942fdd3e7e731cef36ae2fb27ff7caab936634a7f385a973e`.

The two runtime files are unchanged:

- `__init__.py`: SHA-256
  `51aaa569206fd37db1dad8a68f91968c4ff117ee02bfa53f977ac2b6dba9e8f4`
- `plugin.yaml`: SHA-256
  `eceddfc33348bc7b3933e35615da0ff830a58c17381ce67604855d3cae98d5de`

Inherited `tests/test_admission.py` source SHA-256:
`d1a56a332f5c1201d4d3b13d75ada82f89e3bf3af0eed948ba43624edd2e8702`.
All 21 original test method identifiers remain. The 17 synthetic admission test
methods and their two setup/helper methods retain identical ASTs. Native
integration tests are adapted rather than claimed unchanged:

- use repository-root manifest/runtime paths;
- generate a disposable terminal-refusal policy pinned to the selected native
  source/interpreter instead of copying a private host-bound policy;
- replace private product-specific negative constants with synthetic ones;
- bind the expected ordinary refusal to the actual native eligibility predicate,
  while explicitly verifying delegated/non-dispatcher denial too;
- add an inert-public-example regression proving refusal before native authority.

The original native-context assertion assumed every ordinary shell already had
an explicit non-dispatcher fence. Against the documented core, context eligibility
can be true without an owned task: the real plugin correctly refuses
`worker_identity_missing`. No runtime change, marker clearing, weaker permission,
synthetic environment identity or test skip was used to adapt that fixture.

The verifier and its six source-selection regressions are adapted from the
standalone Kanban Review Recording repository. Offline Doctor stages exactly two
runtime files; it does not copy repository scratch or invoke install bootstrap.
CI pins NousResearch/hermes-agent
`f42f579cf8bac4918ac9599bece71618afadd846` and exercises full discovery in normal
and optimized Python 3.14 on Linux. Test dependencies are not plugin dependencies.

No private policy, deployment map, topology, native board, claim lock, product
receipt, held delivery harness or executable helper is distributed. Synthetic
positive fixtures are tests, not dispatcher-owned admission evidence. Extraction
and CI do not authorize merge, installation, runtime promotion or delivery.
