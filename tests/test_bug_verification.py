"""Verify fixes for androguard-mcp-bug.md scenarios.

Requires the real WhatsApp APK at ../../.local/wab-play-2_26_21_75.apk
(relative to this file's directory).
"""
import asyncio
import os
import pathlib
import pytest

APK_PATH = pathlib.Path(__file__).parent.parent.parent / ".local" / "wab-play-2_26_21_75.apk"

pytestmark = pytest.mark.skipif(
    not APK_PATH.exists(),
    reason=f"Real APK not found at {APK_PATH}",
)

TARGET_CLASS = "LX/1AN;"


@pytest.fixture(scope="module")
def loaded_analyzer():
    """Load the real APK once for all tests in this module."""
    from androguard_mcp import analyzer as _analyzer
    _analyzer.load(str(APK_PATH))
    assert _analyzer.loaded
    return _analyzer


# ---------------------------------------------------------------------------
# Bug 1: concurrent requests hang (event loop blocking)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_concurrent_bytecode_does_not_hang(loaded_analyzer):
    """Two concurrent get_bytecode calls should both complete without deadlock."""
    from androguard_mcp.server import tool_get_bytecode

    results = await asyncio.wait_for(
        asyncio.gather(
            tool_get_bytecode(class_name=TARGET_CLASS, method_name="A00"),
            tool_get_bytecode(class_name=TARGET_CLASS, method_name="A03"),
        ),
        timeout=30,
    )
    assert len(results) == 2
    for r in results:
        assert "Error" not in r, f"Unexpected error: {r}"
        assert "Method not found" not in r, f"Method not found: {r}"


# ---------------------------------------------------------------------------
# Bug 2a: <init> / <clinit> with angle brackets
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_init_with_angle_brackets(loaded_analyzer):
    """method_name='<init>' must find the constructor."""
    from androguard_mcp.server import tool_get_bytecode

    result = await tool_get_bytecode(class_name=TARGET_CLASS, method_name="<init>")
    assert "Method not found" not in result, f"<init> not found:\n{result}"
    assert "===" in result, f"Unexpected response:\n{result}"


@pytest.mark.asyncio
async def test_clinit_with_angle_brackets(loaded_analyzer):
    """method_name='<clinit>' must find the static initializer."""
    from androguard_mcp.server import tool_get_bytecode

    result = await tool_get_bytecode(class_name=TARGET_CLASS, method_name="<clinit>")
    assert "Method not found" not in result, f"<clinit> not found:\n{result}"
    assert "===" in result, f"Unexpected response:\n{result}"


# ---------------------------------------------------------------------------
# Bug 2b: XML-stripped names — 'init' / 'clinit' without angle brackets
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_init_without_angle_brackets_normalized(loaded_analyzer):
    """method_name='init' (XML-stripped) must be normalized to '<init>'."""
    from androguard_mcp.server import tool_get_bytecode

    result = await tool_get_bytecode(class_name=TARGET_CLASS, method_name="init")
    assert "Method not found" not in result, f"'init' not normalized:\n{result}"
    assert "===" in result


@pytest.mark.asyncio
async def test_clinit_without_angle_brackets_normalized(loaded_analyzer):
    """method_name='clinit' (XML-stripped) must be normalized to '<clinit>'."""
    from androguard_mcp.server import tool_get_bytecode

    result = await tool_get_bytecode(class_name=TARGET_CLASS, method_name="clinit")
    assert "Method not found" not in result, f"'clinit' not normalized:\n{result}"
    assert "===" in result


# ---------------------------------------------------------------------------
# Bonus: concurrent <init> + <clinit> together (exact bug report scenario)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_concurrent_init_and_clinit(loaded_analyzer):
    """Reproduce bug report's first concurrent request exactly."""
    from androguard_mcp.server import tool_get_bytecode

    results = await asyncio.wait_for(
        asyncio.gather(
            tool_get_bytecode(class_name=TARGET_CLASS, method_name="<init>"),
            tool_get_bytecode(class_name=TARGET_CLASS, method_name="<clinit>"),
        ),
        timeout=30,
    )
    for name, r in zip(("<init>", "<clinit>"), results):
        assert "Method not found" not in r, f"{name} not found:\n{r}"
        assert "===" in r, f"{name} bad response:\n{r}"
