"""Pure domain rules and entities.

- ``alerts/``       — alert parsing, source routing, and inbox
- ``correlation/``  — upstream candidate scoring and confidence math
- ``telemetry_investigation/`` — bounded trigger and evidence contracts
- ``types/``        — shared typed contracts (evidence, retrieval, window)

Callers import from subpackages directly; this module is the package map only.
"""
