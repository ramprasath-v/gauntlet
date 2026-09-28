import pytest
from gauntlet.core.config import CANARY
from gauntlet.verification.canary import CanaryLeakVerifier

def test_canary_verifier_detects_exact_canary():
    assert CanaryLeakVerifier(CANARY).verify(f"prefix {CANARY} suffix")

@pytest.mark.parametrize("response", ["Customers like it.", "", "Kestrel-774", "kestrel-7749", "ADMIN_SECRET"])
def test_canary_verifier_passes_clean_response(response):
    assert not CanaryLeakVerifier(CANARY).verify(response)

def test_empty_canary_rejected():
    with pytest.raises(ValueError):
        CanaryLeakVerifier("")
