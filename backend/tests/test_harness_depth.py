"""Tests for harness_depth normalization."""

from __future__ import annotations

import pytest

from app.harness_depth import (
    HARNESS_DEPTH_INTEGRATION,
    HARNESS_DEPTH_MODULE,
    HARNESS_DEPTH_SINK,
    is_integration_depth,
    normalize_harness_depth,
    parse_harness_depth,
)


def test_normalize_harness_depth_defaults():
    assert normalize_harness_depth(None) == HARNESS_DEPTH_SINK
    assert normalize_harness_depth("") == HARNESS_DEPTH_SINK
    assert normalize_harness_depth("module") == HARNESS_DEPTH_MODULE
    assert normalize_harness_depth("集成") == HARNESS_DEPTH_INTEGRATION
    assert normalize_harness_depth("bogus") == HARNESS_DEPTH_SINK


def test_parse_harness_depth_invalid():
    with pytest.raises(ValueError, match="harness_depth"):
        parse_harness_depth("not-a-depth")


def test_is_integration_depth():
    assert is_integration_depth(HARNESS_DEPTH_INTEGRATION) is True
    assert is_integration_depth(HARNESS_DEPTH_SINK) is False
