#!/usr/bin/python3
"""Tests the ovh_reconciler module."""

import unittest
import src.ovh_reconciler as ovh_reconciler


class TestReconciler(unittest.TestCase):
    """Tests the OVH reconciler module."""
    def testParseLine_ProducesValidARecord(self):
        """Tests that a simple line of DNS record produces the right output."""
        line = 'foo.dodges.it A 10.0.0.1'
        record = ovh_reconciler.parse_line(line)
        self.assertEqual(record.type, ovh_reconciler.Type.A)
        self.assertEqual(record.subdomain, 'foo.dodges.it')
        self.assertEqual(record.target, '10.0.0.1')


if __name__ == '__main__':
    unittest.main()
