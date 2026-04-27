"""Property-based fuzz tests for HoneyTrap parsers and serializers.

These tests use Hypothesis to generate randomized and structured inputs
and assert that protocol parsers behave gracefully under attacker
control: never raise, never hang, never allocate unbounded memory.
"""
