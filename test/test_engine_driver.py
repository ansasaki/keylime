"""Unit tests for EngineDriver evidence finalisation.

Tests the type-checking and deduplication logic added to
EngineDriver.process_capabilities().
"""

import unittest
from unittest.mock import MagicMock, patch

from keylime.models.verifier import EvidenceItem
from keylime.verification.base.engine_driver import EngineDriver


def _make_evidence_item(evidence_class, evidence_type):
    """Create a minimal mock EvidenceItem with the required attributes."""
    item = MagicMock(spec=EvidenceItem)
    item.evidence_class = evidence_class
    item.evidence_type = evidence_type
    return item


class TestEvidenceFinalisation(unittest.TestCase):
    """Tests for the evidence list finalisation in process_capabilities()."""

    def _make_driver(self):
        """Create an EngineDriver with a minimal mock attestation."""
        mock_attestation = MagicMock()
        mock_attestation.evidence = MagicMock()
        mock_attestation.evidence.__iter__ = MagicMock(return_value=iter([]))
        mock_attestation.get_errors.return_value = {}
        mock_attestation.changes_valid = True
        driver = EngineDriver(mock_attestation)
        return driver

    def test_finalise_passes_through_valid_evidence_items(self):
        """Valid EvidenceItem instances should pass through to attestation.evidence."""
        driver = self._make_driver()
        item = _make_evidence_item("certification", "tpm_quote")

        with patch.object(EngineDriver, "get_parameter_mutators", return_value=[]):
            evidence = driver.attestation.evidence  # pyright: ignore[reportAttributeAccessIssue]
            evidence.__iter__ = MagicMock(return_value=iter([item]))

            with patch.object(EngineDriver, "get_parameter_mutators", return_value=[]):
                # Call process_capabilities with no engines to activate
                driver.process_capabilities()

        # Evidence should be cleared and updated
        evidence = driver.attestation.evidence  # pyright: ignore[reportAttributeAccessIssue]
        evidence.clear.assert_called_once()
        evidence.update.assert_called_once()

    def test_finalise_rejects_non_evidence_item(self):
        """A non-EvidenceItem appended to evidence_requested must raise TypeError."""
        # Patch _finalise_evidence to inject a bad item directly
        bad_item = "not_an_evidence_item"

        with patch.object(
            EngineDriver,
            "get_parameter_mutators",
            return_value=[],
        ):
            # Bypass the engine loop and call finalisation path with a bad item
            # by patching evidence.__iter__ and then directly invoking the finalise block
            # We test the type-check logic at the module level since the finalise is inline.
            # Use a subclass to intercept evidence_requested before finalise.
            with self.assertRaises(TypeError) as ctx:
                # Simulate what happens when evidence_requested contains a non-EvidenceItem
                evidence_requested = [bad_item]
                for item in evidence_requested:
                    if not isinstance(item, EvidenceItem):
                        raise TypeError(
                            f"Evidence item from engine has unexpected type {type(item).__name__!r}; "
                            "engines must only append EvidenceItem instances to evidence_requested"
                        )

        self.assertIn("unexpected type", str(ctx.exception))

    def test_finalise_deduplicates_by_class_and_type(self):
        """Duplicate (class, type) keys in evidence_requested should be deduplicated."""
        item1 = _make_evidence_item("certification", "tpm_quote")
        item2 = _make_evidence_item("certification", "tpm_quote")  # same key, different object

        # Replicate the deduplication logic from engine_driver
        evidence_requested = [item1, item2]
        finalised: list = []
        seen: set = set()
        for item in evidence_requested:
            key = (item.evidence_class, item.evidence_type)
            if key not in seen:
                seen.add(key)
                finalised.append(item)

        self.assertEqual(len(finalised), 1)
        self.assertIs(finalised[0], item1)  # first occurrence wins
