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
                id=0,
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
        record = ovh_reconciler.Record(
                id=42, type=ovh_reconciler.Type.A,
                subdomain='foo', target='10.0.0.1')
        ovh_reconciler.delete_record(record, client)
        client.delete.assert_called_once_with(
                '/domain/zone/foo.com/record/42')

    def testRecordByType_SortsByType(self):
        record_a_1 = ovh_reconciler.Record(
                id=0, type=ovh_reconciler.Type.A,
                subdomain='foo', target='10.0.0.1')
        record_a_2 = ovh_reconciler.Record(
                id=0, type=ovh_reconciler.Type.A,
                subdomain='bar', target='10.1.0.1')
        record_aaaa = ovh_reconciler.Record(
                id=0, type=ovh_reconciler.Type.AAAA,
                subdomain='fo6', target='fe::1')
        records = set()
        records.add(record_a_1)
        records.add(record_a_2)
        records.add(record_aaaa)
        records_by_type = ovh_reconciler.sort_records_by_type(records)
        want_set = set()
        want_set.add(record_aaaa)
        self.assertEqual(len(records_by_type), 2)
        self.assertCountEqual(
                records_by_type[ovh_reconciler.Type.AAAA], want_set)
        want_set = set()
        want_set.add(record_a_1)
        want_set.add(record_a_2)
        self.assertCountEqual(records_by_type[ovh_reconciler.Type.A], want_set)

    @patch('ovh.Client')
    def testReconcile_AddsCorrectly(self, mock_ovh_class):
        record_a_1 = ovh_reconciler.Record(
            id=5, type=ovh_reconciler.Type.A,
            subdomain='foo', target='10.0.0.1')
        intent = set([record_a_1])
        current = set()
        with patch.object(ovh_reconciler, 'add_record') as add_mock:
            client = mock_ovh_class()
            ovh_reconciler.reconcile(intent, current, client)
            add_mock.assert_called_once_with(record_a_1, client)

    @patch('ovh.Client')
    def testReconcile_RemovesCorrectly(self, mock_ovh_class):
        record_a_1 = ovh_reconciler.Record(
            id=5, type=ovh_reconciler.Type.A,
            subdomain='foo', target='10.0.0.1')
        intent = set()
        current = set([record_a_1])
        with patch.object(ovh_reconciler, 'delete_record') as delete_mock:
            client = mock_ovh_class()
            ovh_reconciler.reconcile(intent, current, client)
            delete_mock.assert_called_once_with(record_a_1, client)

    @patch('ovh.Client')
    def testReconcile_ModifiesRecordWithDifferentTarget(self, mock_ovh_class):
        record_a_1 = ovh_reconciler.Record(
            id=5, type=ovh_reconciler.Type.A,
            subdomain='foo', target='10.0.0.1')
        record_a_2 = ovh_reconciler.Record(
            id=5, type=ovh_reconciler.Type.A,
            subdomain='foo', target='10.0.0.2')
        intent = set([record_a_2])
        current = set([record_a_1])
        with patch.object(ovh_reconciler, 'add_record') as add_mock:
            with patch.object(ovh_reconciler, 'delete_record') as delete_mock:
                client = mock_ovh_class()
                ovh_reconciler.reconcile(intent, current, client)
                delete_mock.assert_called_once_with(record_a_1, client)
                add_mock.assert_called_once_with(record_a_2, client)

    @patch('ovh.Client')
    def testReconcile_DoesNotModifyExistingRecords(self, mock_ovh_class):
        record_a = ovh_reconciler.Record(
            id=5, type=ovh_reconciler.Type.A,
            subdomain='foo', target='10.0.0.1')
        intent = set([record_a])
        current = set([record_a])
        with patch.object(ovh_reconciler, 'add_record') as add_mock:
            with patch.object(ovh_reconciler, 'delete_record') as delete_mock:
                client = mock_ovh_class()
                ovh_reconciler.reconcile(intent, current, client)
                delete_mock.assert_not_called()
                add_mock.assert_not_called()

    @patch('ovh.Client')
    def testReconcile_IgnoresUnallowedTypes(self, mock_ovh_class):
        record_mx = ovh_reconciler.Record(
            id=5, type=ovh_reconciler.Type.MX,
            subdomain='foo', target='10.0.0.1')
        record_tlsa = ovh_reconciler.Record(
            id=5, type=ovh_reconciler.Type.TLSA,
            subdomain='foo', target='10.0.0.1')
        intent = set([record_mx])
        current = set([record_tlsa])
        with patch.object(ovh_reconciler, 'add_record') as add_mock:
            with patch.object(ovh_reconciler, 'delete_record') as delete_mock:
                client = mock_ovh_class()
                ovh_reconciler.reconcile(intent, current, client)
                delete_mock.assert_not_called()
                add_mock.assert_not_called()


if __name__ == '__main__':
    absltest.main()
