"""Scenario engine: generic scenario manifests, injection, runner and formal trace.

Sits ABOVE the security engine (firewall, guard, audit, sandbox, approval, model adapter) and
never changes it. The engine does not learn about domains here. blocked_at and penetration depth
are OBSERVED outputs; a manifest may not carry an expected one.
"""
