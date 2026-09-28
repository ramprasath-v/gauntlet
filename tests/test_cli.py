import argparse
import pytest
from gauntlet.cli import local_target

@pytest.mark.parametrize("target", ["https://example.com", "http://192.0.2.1", "http://localhost.evil", "http://localhost/path", "http://user:pass@localhost", "http://localhost?redirect=1"])
def test_external_or_ambiguous_targets_rejected(target):
    with pytest.raises(argparse.ArgumentTypeError):
        local_target(target)

def test_localhost_pinned_to_loopback():
    assert local_target("http://localhost:8001") == "http://127.0.0.1:8001"
