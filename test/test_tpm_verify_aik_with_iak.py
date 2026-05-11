"""Unit tests for Tpm.verify_aik_with_iak() function."""

import hashlib
import struct
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa

from keylime.tpm import tpm2_objects
from keylime.tpm.tpm_main import Tpm


def _build_attest(extra_data: bytes, ak_name: bytes) -> bytes:
    """Build a minimal TPMS_ATTEST structure for TPM2_Certify.

    Layout:
      magic(4) + type(2) = 6-byte header
      qualifiedSigner: TPM2B_NAME (2-byte size + data)
      extraData: TPM2B_DATA (2-byte size + data)
      clockInfo: TPMS_CLOCK_INFO (17 bytes: clock(8) + resetCount(4) + restartCount(4) + safe(1))
      firmwareVersion(8)
      certifyInfo: TPMS_CERTIFY_INFO = TPM2B_NAME(qualifiedName) + TPM2B_NAME(name)
    """
    header = b"\xff\x54\x43\x47" + b"\x80\x17"  # magic + TPM_ST_ATTEST_CERTIFY
    qualified_signer = struct.pack(">H", 4) + b"\x00" * 4
    extra_data_field = struct.pack(">H", len(extra_data)) + extra_data
    clock_info = b"\x00" * 17
    firmware_version = b"\x00" * 8
    # TPMS_CERTIFY_INFO: name (TPM2B_NAME) then qualifiedName (TPM2B_NAME)
    name_field = struct.pack(">H", len(ak_name)) + ak_name
    qualified_name = struct.pack(">H", 2) + b"\x00\x00"
    certify_info = name_field + qualified_name

    return header + qualified_signer + extra_data_field + clock_info + firmware_version + certify_info


def _build_sig(sig_alg: int, hash_alg: int, signature: bytes) -> bytes:
    """Build a minimal TPMT_SIGNATURE structure for RSASSA."""
    return struct.pack(">HHH", sig_alg, hash_alg, len(signature)) + signature


# Fixed 34-byte AK name (nameAlg(2) + SHA-256(32))
AK_NAME = b"\x00\x0b" + b"\xaa" * 32
AK_NAME_HEX = AK_NAME.hex()


class TestVerifyAikWithIak(unittest.TestCase):
    """Test cases for Tpm.verify_aik_with_iak() qualifying data handling."""

    def setUp(self):
        self.uuid = "d432fbb3-d2f1-4a97-9ef7-75bd81c00000"
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()
        self.aik_tpm = b"\x00\x01" + b"\x00" * 100
        self.iak_tpm = b"\x00\x01" + b"\x00" * 100
        self.fake_sig = b"\x00" * 256

    def _run_verify(self, extra_data: bytes, expect_result: bool = True) -> bool:
        """Run verify_aik_with_iak with the given extra_data, mocking internals."""
        attest = _build_attest(extra_data, AK_NAME)
        sig = _build_sig(tpm2_objects.TPM_ALG_RSASSA, tpm2_objects.TPM_ALG_SHA256, self.fake_sig)

        with (
            patch("keylime.tpm.tpm2_objects.pubkey_from_tpm2b_public") as mock_pubkey,
            patch("keylime.tpm.tpm2_objects.get_tpm2b_public_name") as mock_name,
            patch("keylime.tpm.tpm_util.crypt_hash") as mock_hash,
            patch("keylime.tpm.tpm_util.verify") as mock_verify,
        ):
            mock_pubkey.return_value = self.public_key
            mock_name.return_value = AK_NAME_HEX
            mock_hash.return_value = (b"\x00" * 32, hashes.SHA256())
            mock_verify.return_value = None

            return Tpm.verify_aik_with_iak(self.uuid, self.aik_tpm, self.iak_tpm, attest, sig)

    def test_hashed_qualifying_data(self):
        """New agents (>= 2.6) send SHA-256(uuid) as qualifying data."""
        extra_data = hashlib.sha256(self.uuid.encode("utf-8")).digest()
        self.assertTrue(self._run_verify(extra_data))

    def test_raw_qualifying_data(self):
        """Old agents (< 2.6) send raw uuid bytes as qualifying data."""
        extra_data = self.uuid.encode("utf-8")
        self.assertTrue(self._run_verify(extra_data))

    def test_mismatched_qualifying_data(self):
        """Qualifying data that matches neither hash nor raw should fail."""
        extra_data = b"wrong-qualifying-data"
        self.assertFalse(self._run_verify(extra_data))

    def test_wrong_ak_name(self):
        """Verification should fail when AK name doesn't match."""
        extra_data = hashlib.sha256(self.uuid.encode("utf-8")).digest()
        wrong_ak_name = b"\x00\x0b" + b"\xbb" * 32
        attest = _build_attest(extra_data, wrong_ak_name)
        sig = _build_sig(tpm2_objects.TPM_ALG_RSASSA, tpm2_objects.TPM_ALG_SHA256, self.fake_sig)

        with (
            patch("keylime.tpm.tpm2_objects.pubkey_from_tpm2b_public") as mock_pubkey,
            patch("keylime.tpm.tpm2_objects.get_tpm2b_public_name") as mock_name,
        ):
            mock_pubkey.return_value = self.public_key
            mock_name.return_value = AK_NAME_HEX  # expects the standard AK_NAME

            result = Tpm.verify_aik_with_iak(self.uuid, self.aik_tpm, self.iak_tpm, attest, sig)

        self.assertFalse(result)

    def test_long_agent_id_hashed(self):
        """Agent IDs longer than 34 bytes work when hashed."""
        long_uuid = "a" * 100
        extra_data = hashlib.sha256(long_uuid.encode("utf-8")).digest()
        attest = _build_attest(extra_data, AK_NAME)
        sig = _build_sig(tpm2_objects.TPM_ALG_RSASSA, tpm2_objects.TPM_ALG_SHA256, self.fake_sig)

        with (
            patch("keylime.tpm.tpm2_objects.pubkey_from_tpm2b_public") as mock_pubkey,
            patch("keylime.tpm.tpm2_objects.get_tpm2b_public_name") as mock_name,
            patch("keylime.tpm.tpm_util.crypt_hash") as mock_hash,
            patch("keylime.tpm.tpm_util.verify") as mock_verify,
        ):
            mock_pubkey.return_value = self.public_key
            mock_name.return_value = AK_NAME_HEX
            mock_hash.return_value = (b"\x00" * 32, hashes.SHA256())
            mock_verify.return_value = None

            result = Tpm.verify_aik_with_iak(long_uuid, self.aik_tpm, self.iak_tpm, attest, sig)

        self.assertTrue(result)


if __name__ == "__main__":
    unittest.main()
