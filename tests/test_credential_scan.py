from gauntlet.core.credential_scan import credential_issue


def test_ordinary_security_language_and_source_are_not_credentials():
    evidence = {
        "rationale": "authorization: skip unauthorized context",
        "source": (
            "authorization_grants = find_authorization(context)\n"
            "token: describes the policy concept without a credential value"
        ),
    }
    assert credential_issue(evidence) is None


def test_bearer_material_is_rejected_in_raw_and_structured_values():
    bearer = "Bearer synthetic-token-1234567890"
    assert credential_issue(f"Authorization: {bearer}") == "credential_marker"
    assert credential_issue({"authorization": bearer}) == "credential_marker"


def test_structured_api_key_and_raw_secret_assignments_are_rejected():
    assert credential_issue({
        "api_key": "sk-synthetic-1234567890",
    }) == "credential_marker"
    assert credential_issue(
        "access_token=synthetic-access-token-1234567890"
    ) == "credential_marker"
    assert credential_issue(
        "secret=synthetic-secret-value-1234567890"
    ) == "credential_marker"


def test_configured_credential_is_rejected_anywhere_without_exposing_it():
    configured = "configured-synthetic-nebius-key-12345"
    assert credential_issue(
        {"provider_output": f"unexpected echo: {configured}"},
        configured_credentials=(configured,),
    ) == "configured_credential"
