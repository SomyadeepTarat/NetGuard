import tempfile
import unittest
from pathlib import Path
from scapy.all import Ether, IP, TCP, wrpcap

from backend.services.pcap_resolver import (
    resolve_safe_pcap_path,
    compute_pcap_fingerprint,
    verify_pcap_unmodified,
    PcapSecurityError,
)


class TestPcapResolver(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Create a tiny valid PCAP inside artifacts/demo or tests
        cls.test_pcap = Path("tests/fixtures/sample_resolver_test.pcap")
        cls.test_pcap.parent.mkdir(parents=True, exist_ok=True)
        pkt = Ether() / IP(src="192.168.1.10", dst="192.168.1.1") / TCP(sport=1234, dport=80, flags="S")
        wrpcap(str(cls.test_pcap), [pkt])

    @classmethod
    def tearDownClass(cls):
        if cls.test_pcap.exists():
            cls.test_pcap.unlink()

    def test_safe_resolution_valid_file(self):
        resolved = resolve_safe_pcap_path("tests/fixtures/sample_resolver_test.pcap")
        self.assertTrue(resolved.exists())
        self.assertEqual(resolved.suffix.lower(), ".pcap")

    def test_traversal_attack_rejected(self):
        with self.assertRaises(PcapSecurityError) as ctx:
            resolve_safe_pcap_path("../../../windows/system32/cmd.exe")
        self.assertIn("traversal", str(ctx.exception).lower())

    def test_absolute_path_outside_allowed_roots_rejected(self):
        with self.assertRaises(PcapSecurityError) as ctx:
            resolve_safe_pcap_path("C:/Windows/secret.pcap")
        self.assertIn("restricted", str(ctx.exception).lower())

    def test_disallowed_extension_rejected(self):
        with self.assertRaises(PcapSecurityError) as ctx:
            resolve_safe_pcap_path("backend/main.py")
        self.assertIn("extension", str(ctx.exception).lower())

    def test_missing_file_raises_not_found(self):
        with self.assertRaises(FileNotFoundError):
            resolve_safe_pcap_path("artifacts/demo/nonexistent_sample_never_exists.pcap")

    def test_fingerprint_and_non_mutation(self):
        sha, size = compute_pcap_fingerprint(self.test_pcap)
        self.assertEqual(len(sha), 64)
        self.assertGreater(size, 0)
        self.assertTrue(verify_pcap_unmodified(self.test_pcap, sha))
        self.assertFalse(verify_pcap_unmodified(self.test_pcap, "0" * 64))


if __name__ == "__main__":
    unittest.main()
