from src.service.kyc_server import (
    classify_document,
    extract_ubos,
    validate_required_docs,
)


def test_extract_ubos_masks_pii():
    ubos = extract_ubos("acme_corp")
    assert "[EMAIL]" in ubos
    assert any("[PHONE]" in u for u in ubos)


def test_classify_document():
    assert classify_document("This is my passport") == "passport"
    assert (
        classify_document("Here is a utility bill for address verification")
        == "proof_of_address"
    )
    assert (
        classify_document("certificate of incorporation for company")
        == "registration"
    )
    assert classify_document("mystery document") == "unknown"


def test_validate_required_docs():
    assert validate_required_docs("acme_corp", ["registration", "director_id"])
    assert not validate_required_docs("acme_corp", ["registration"])
    assert validate_required_docs("bob", ["id", "proof_of_address"])
    assert not validate_required_docs("bob", ["id"])
