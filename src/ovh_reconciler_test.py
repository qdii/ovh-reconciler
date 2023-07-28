#!/usr/bin/python3
"""Tests the ovh_reconciler module."""

import ovh
import unittest
from absl.testing import absltest
from absl.testing import flagsaver
from parameterized import parameterized
from unittest.mock import patch
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
        'muffin IN CNAME 10.0.0.1',
        'muffin IN CNAME 2001:41d0:401::1',
        '2001:41d0:401::1 IN CNAME foo',
        '10.0.0.1 IN CNAME foo',
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

    @parameterized.expand([
        ('mail IN CNAME  ssl0.ovh.net.', 'mail', 'ssl0.ovh.net.'),
        ('muffin  IN CNAME  swip.dodges.it.', 'muffin', 'swip.dodges.it.'),
    ])
    def testParseValidCNAMERecord_ProducesValidRecord(
            self, line: str, subdomain: str, target: str):
        record = ovh_reconciler.parse_line(line)
        self.assertEqual(record.type, ovh_reconciler.Type.CNAME)
        self.assertEqual(record.subdomain, subdomain)
        self.assertEqual(record.target, target)

    @flagsaver.flagsaver(dns_zone='foo.com')
    @patch('ovh.Client')
    def testFetchRecords_CallsOVHClient(self, mock_ovh_class):
        client = mock_ovh_class()
        ovh_reconciler.fetch_records(ovh_reconciler.Type.A, client)
        client.get.assert_called_once_with(
                '/domain/zone/foo.com/record', fieldType='A')

    @flagsaver.flagsaver(dns_zone='foo.com')
    @patch('ovh.Client')
    def testAddRecord_CallsOVHClient(self, mock_ovh_class):
        client = mock_ovh_class()
        record = ovh_reconciler.Record(
                type=ovh_reconciler.Type.AAAA,
                subdomain='foo',
                target='2001:41d0:401::1')
        ovh_reconciler.add_record(record, client)
        client.post.assert_called_once_with(
                '/domain/zone/foo.com/record', fieldType='AAAA',
                subDomain='foo', target='2001:41d0:401::1')

    @flagsaver.flagsaver(dns_zone='foo.com')
    @patch('ovh.Client')
    def testDeleteRecord_CallsOVHClient(self, mock_ovh_class):
        client = mock_ovh_class()
        ovh_reconciler.delete_record(42, client)
        client.delete.assert_called_once_with(
                '/domain/zone/foo.com/record/42')


if __name__ == '__main__':
    absltest.main()
