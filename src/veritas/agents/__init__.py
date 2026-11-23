"""Model roles (docs/architecture.md §10.1): triage, analyst, reviewer, and remediator.

Each role is one schema-constrained model task. Roles never decide a finding's status,
never send traffic, and never see raw evidence IDs; every reference they make is checked.
The planner role is deferred: the rule planner already plans every registry check on
every route it applies to, so a planner could only propose duplicates until Phase 4
brings third-party checks.
"""
