import unittest
from src.supply_chain_verifier import SupplyChainVerifier


class TestSupplyChainVerifier(unittest.TestCase):
    def setUp(self):
        self.verifier = SupplyChainVerifier()
        self.valid_digest = "a" * 64
        self.valid_statement = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [
                {
                    "name": "ghcr.io/bhomesh/secure-service",
                    "digest": {"sha256": self.valid_digest},
                }
            ],
            "predicateType": "https://slsa.dev/provenance/v0.2",
            "predicate": {
                "builder": {
                    "id": "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.0.0"
                },
                "buildType": "https://github.com/slsa-framework/slsa-github-generator/generic@v1",
                "invocation": {
                    "configSource": {
                        "uri": "git+https://github.com/Bhomesh/zero-trust-devsecops-pipeline@refs/heads/main"
                    }
                },
                "materials": [
                    {
                        "uri": "git+https://github.com/Bhomesh/zero-trust-devsecops-pipeline",
                        "digest": {"sha1": "abcdef1234567890abcdef1234567890abcdef12"},
                    }
                ],
            },
        }

    def test_verify_valid_in_toto_statement(self):
        is_valid, errors = self.verifier.verify_in_toto_statement(self.valid_statement)
        self.assertTrue(is_valid)
        self.assertEqual(errors, [])

    def test_verify_invalid_statement_type(self):
        bad_stmt = dict(self.valid_statement)
        bad_stmt["_type"] = "invalid-type"
        is_valid, errors = self.verifier.verify_in_toto_statement(bad_stmt)
        self.assertFalse(is_valid)
        self.assertTrue(any("Invalid in-toto statement _type" in e for e in errors))

    def test_verify_invalid_subject_digest(self):
        bad_stmt = dict(self.valid_statement)
        bad_stmt["subject"] = [{"name": "bad", "digest": {"sha256": "not-a-64-hex"}}]
        is_valid, errors = self.verifier.verify_in_toto_statement(bad_stmt)
        self.assertFalse(is_valid)
        self.assertTrue(any("not a valid 64-hex string" in e for e in errors))

    def test_verify_valid_slsa_provenance(self):
        is_valid, errors = self.verifier.verify_slsa_provenance(self.valid_statement, expected_digest=self.valid_digest)
        self.assertTrue(is_valid)
        self.assertEqual(errors, [])

    def test_verify_untrusted_builder(self):
        untrusted_stmt = json_copy(self.valid_statement)
        untrusted_stmt["predicate"]["builder"]["id"] = "https://evil.builder/pipeline"
        is_valid, errors = self.verifier.verify_slsa_provenance(untrusted_stmt)
        self.assertFalse(is_valid)
        self.assertTrue(any("Untrusted builder ID" in e for e in errors))

    def test_cosign_signature_mock(self):
        valid_ref = f"ghcr.io/bhomesh/app@sha256:{self.valid_digest}"
        ok, msg = self.verifier.verify_cosign_signature(valid_ref)
        self.assertTrue(ok)
        self.assertIn("digest validated", msg)

        mutable_ref = "ghcr.io/bhomesh/app:latest"
        ok, msg = self.verifier.verify_cosign_signature(mutable_ref)
        self.assertFalse(ok)
        self.assertIn("Cannot verify unsigned mutable tag", msg)


def json_copy(data):
    import json
    return json.loads(json.dumps(data))


if __name__ == "__main__":
    unittest.main()
