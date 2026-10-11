# MAZE evidence adapter

This fork retains the upstream model and selected smell engines. `maze_headless.py`
accepts a fingerprinted JSON model from static facts and runs explicitly selected
detectors without the web application, targets, endpoints or filesystem logging.
Spring and Quarkus extraction belongs to MAZE; the core is framework independent.

`JSONImporter(preserve_unknown=True)` preserves omitted/null timeout,
circuit-breaker and dynamic-discovery properties as `None`. Known values must be
booleans. Legacy imports retain their existing default-false behavior. The upstream
detector predicates compare against false, so unknowns cannot establish absence.
The headless result includes per-link coverage for selected rules with unknowns.

The MAZE pilot selects shared persistence and bounded direct-client wobbly
interactions. Protocol 2 requires stable opaque `evidence_id` strings on links;
parallel operations retain separate identities through import and result causes.
Protocol 1 remains accepted for existing callers. Discovery, gateway, team and
co-hosting findings require evidence MAZE does not currently establish.
Refactoring descriptions are suggestions, never applied to application sources.

```sh
uv sync --locked
uv run python -m unittest tests.test_maze_headless -v
uv run python maze_headless.py --input evidence.json --detector shared-persistency
```

The headless dependency lock targets Python 3.13. The historical full suite has
preexisting failures in team smells and missing optional Kubernetes-refiner
dependencies; these are outside the pilot. Compare upstream revision
`d20505555efbfd6a06a9dbebeccaaca5698e7c7d` under the same interpreter/dependencies
before attributing failures to this fork. Relevant model, JSON importer and selected
detector tests are run separately. No cycle detector exists in this upstream core.
