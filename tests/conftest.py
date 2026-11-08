import pytest

from netsentinel.detector import Detector
from netsentinel.train import simulated


@pytest.fixture(scope="session")
def detector():
    X, y = simulated(range(1, 4), duration=400)
    return Detector().fit(X, y)
