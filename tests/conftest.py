import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

# Suppress androguard loguru noise before imports
from loguru import logger
logger.remove()

from androguard_mcp import analyzer as _global_analyzer

APK_PATH = os.path.join(
    os.path.dirname(__file__), "..", "com.google.android.deskclock.apk"
)
SKIP_INTEGRATION = not os.path.exists(APK_PATH)

requires_apk = pytest.mark.skipif(
    SKIP_INTEGRATION,
    reason="APK not found at .local/wab-play-2_26_21_75.apk",
)


@pytest.fixture(scope="session")
def loaded_analyzer():
    """Session-scoped: loads APK once for all integration tests."""
    if SKIP_INTEGRATION:
        pytest.skip("APK not found")
    _global_analyzer.load(APK_PATH)
    return _global_analyzer
