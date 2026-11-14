from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def malicious_skill() -> str:
    return str(FIXTURES / "malicious_skill")


@pytest.fixture
def benign_skill() -> str:
    return str(FIXTURES / "benign_skill")


@pytest.fixture
def mcp_skill() -> str:
    return str(FIXTURES / "mcp_skill")


@pytest.fixture
def taint_skill() -> str:
    return str(FIXTURES / "taint_skill")


@pytest.fixture
def benign_docs_skill() -> str:
    return str(FIXTURES / "benign_docs_skill")
