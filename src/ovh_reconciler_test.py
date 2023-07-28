#!/usr/bin/python3
"""Tests the ovh_reconciler module."""

import unittest
from parameterized import parameterized
import src.ovh_reconciler as ovh_reconciler


class TestReconciler(unittest.TestCase):
    """Tests the OVH reconciler module."""

    @parameterized.expand([
        'foo.dodges.it A 10.0.0.1',
        ' foo.dodges.it   A   10.0.0.1 ',
        'foo.dodges.it\tA 10.0.0.1',
        ])
    def testParseValidLine_ProducesValidARecord(self, line):
        """Tests that a simple line of DNS record produces the right output."""
        record = ovh_reconciler.parse_line(line)
        self.assertEqual(record.type, ovh_reconciler.Type.A)
        self.assertEqual(record.subdomain, 'foo.dodges.it')
        self.assertEqual(record.target, '10.0.0.1')

    @parameterized.expand([
        '', ' ', '\t', '# A 10.0.0.1', 'A 10.0.0.1',
        ])
    def testParseInvalidLine_ReturnsNone(self, line):
        """Tests that invalid line do not return a Record object."""
        self.assertIsNone(ovh_reconciler.parse_line(line))

    @parameterized.expand([
            'ovh              IN AAAA   2001:41d0:401:3200::1d20',
        ])
    def testParseValidAAAARecord_ProducesValidRecord(self, line):
        record = ovh_reconciler.parse_line(line)
        self.assertEqual(record.type, ovh_reconciler.Type.AAAA)
        self.assertEqual(record.subdomain, 'ovh')
        self.assertEqual(record.target, '2001:41d0:401:3200::1d20')



if __name__ == '__main__':
    unittest.main()
