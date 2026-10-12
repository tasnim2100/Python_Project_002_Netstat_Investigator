import pathlib
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from netstat_monitor import (Connection, annotate, classify, clean_ip, display_endpoint,
                             is_public_ip, parse_netstat, parse_tasklist, split_endpoint)
from reputation import lookup_ip, summarize_reputation

SAMPLE = """Active Connections
  Proto  Local Address          Foreign Address        State           PID
  TCP    192.168.1.10:50210     8.8.8.8:443            ESTABLISHED     1111
  TCP    192.168.1.10:50211     1.1.1.1:4444           ESTABLISHED     2222
  TCP    [::1]:53143           [::1]:53144           ESTABLISHED     3333
  TCP    [2001:db8::1]:51515  [2606:4700:4700::1111]:443 ESTABLISHED 4444
  TCP    0.0.0.0:445           0.0.0.0:0             LISTENING       2222
  UDP    0.0.0.0:5353          *:*                                  2222
"""

class TestNetstat(unittest.TestCase):
    def test_parser_established_only(self):
        c = parse_netstat(SAMPLE)
        self.assertEqual(len(c), 4)
        self.assertEqual(c[0].pid, 1111)
        self.assertEqual(c[1].remote_port, 4444)

    def test_ipv6(self):
        c = parse_netstat(SAMPLE)
        self.assertEqual(c[2].remote_ip, "::1")
        self.assertEqual(c[3].remote_ip, "2606:4700:4700::1111")
        self.assertEqual(display_endpoint(c[2].remote_ip, 80), "[::1]:80")

    def test_split_endpoint(self):
        self.assertEqual(split_endpoint("[fe80::abc%9]:443"), ("fe80::abc%9", 443))
        with self.assertRaises(ValueError):
            split_endpoint("badendpoint")

    def test_tasklist_csv(self):
        sample = '"chrome.exe","1,111","Console","1","22,000 K"\n"powershell.exe","2222","Console","1","1,500 K"'
        self.assertEqual(parse_tasklist(sample), {1111:"chrome.exe",2222:"powershell.exe"})

    def test_public_ip_filter(self):
        self.assertTrue(is_public_ip("8.8.8.8"))
        self.assertTrue(is_public_ip("2606:4700:4700::1111"))
        self.assertFalse(is_public_ip("127.0.0.1"))
        self.assertFalse(is_public_ip("192.168.1.10"))
        self.assertFalse(is_public_ip("203.0.113.8"))
        self.assertEqual(str(clean_ip("::ffff:8.8.8.8")), "8.8.8.8")

    def test_common_port_is_routine(self):
        self.assertEqual(classify(Connection("192.168.0.4", 51000, "8.8.8.8", 443, 1))[0], "Routine")

    def test_unusual_port_is_review(self):
        level, message = classify(Connection("192.168.0.4", 51000, "8.8.8.8", 4444, 1))
        self.assertEqual(level, "Review")
        self.assertIn("4444", message)

    def test_script_host_is_review(self):
        level, _ = classify(Connection("192.168.0.4", 51000, "8.8.8.8", 443, 1, "powershell.exe"))
        self.assertEqual(level, "Review")

    def test_local_ip_is_not_public(self):
        self.assertEqual(classify(Connection("192.168.0.4", 51000, "127.0.0.1", 4444, 1))[0], "Local")

    def test_inbound_local_service(self):
        level, msg = classify(Connection("192.168.0.4", 3389, "8.8.8.8", 51000, 1))
        self.assertEqual(level, "Review")
        self.assertIn("local service", msg)

    def test_annotate_and_prioritize(self):
        result = annotate(parse_netstat(SAMPLE), {1111:"browser.exe",2222:"script.exe"})
        self.assertEqual(result[0].risk, "Review")
        self.assertEqual(sum(r.risk == "Review" for r in result), 1)

    def test_reputation_rejects_private_address(self):
        with self.assertRaises(ValueError):
            lookup_ip("127.0.0.1", "fake-key")

    def test_reputation_needs_key(self):
        with self.assertRaises(ValueError):
            lookup_ip("8.8.8.8", "")

    def test_reputation_summary(self):
        self.assertIn("60/100", summarize_reputation({"abuseConfidenceScore":60,"totalReports":8}))

if __name__ == "__main__":
    unittest.main()
