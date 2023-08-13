#!/usr/bin/python3
"""Updates a DNS zone stored in OVH from a simple text file."""

import fileinput
import ovh
import re
from typing import Dict, NamedTuple, Set
from enum import Enum
from absl import app
from absl import flags
from absl import logging


FLAGS = flags.FLAGS

flags.DEFINE_string(
    'application_key', '',
    'A key given by OVH upon registering to api.ovh.com')

flags.DEFINE_string(
    'application_secret', '',
    'A secret given by OVH upon registering to api.ovh.com')

flags.DEFINE_string(
    'consumer_key', '',
    'A key given by OVH upon registering to api.ovh.com. It is attached to '
    'your account')

flags.DEFINE_string(
    'dns_zone', '',
    'The DNS zone to administer. For instance "dodges.it".')

_DRY_RUN = flags.DEFINE_bool(
    'dry_run', False,
    'If True, no records are created or deleted.')


# TODO: This accepts invalid IPs, such as 999.999.999.999. Make it stricter.
RE_IPV4 = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
RE_IPV6 = r'(([a-f0-9:]+:+)+[a-f0-9]+)'
RE_SUBDOMAIN = r'([-.a-zA-Z0-9_]+)'
RE_RECORD_A = r'\s*' + RE_SUBDOMAIN + r'\s+' + 'A' + r'\s+' + RE_IPV4 + r'\s*'
RE_RECORD_AAAA = r'\s*' + RE_SUBDOMAIN + r'\s+IN\s+AAAA\s+' + RE_IPV6 + r'\s*'
RE_RECORD_CNAME = r'\s*' + RE_SUBDOMAIN + r'\s+IN\s+CNAME\s+' + RE_SUBDOMAIN + r'\s*'  # pylint: disable=line-too-long


class Type(Enum):
    """The different types of DNS records.

    For details see RFC 1034."""
    A = 1
    AAAA = 2
    CNAME = 3
    DKIM = 4
    DMARC = 5
    DNAME = 6
    LOC = 7
    MX = 8
    NAPTR = 9
    NS = 10
    SPF = 11
    SRV = 12
    SSHFP = 13
    TLSA = 14
    TXT = 15


# The types that are reconciled. Other types are ignored.
ALLOWED_TYPES = [
    Type.A,
    Type.AAAA,
    Type.CNAME,
]


class Record(NamedTuple):
    """A DNS record."""
    # The type of DNS record. Either 'A', 'AAAA', etc.
    type: Type

    # The subdomain the record is pointing to. For instance, an A record
    # could link the subdomain foo.dodges.it to the IP address '5.1.4.1'A.
    subdomain: str

    # The thing the record resolves to. In the case of a A record it's an IPv4,
    # in the case of CNAME it's a domain name.
    target: str

    # The id of the record, as returned by OVH. If OVH doesn't know this record
    # then this field is 0.
    id: int

    def __str__(self) -> str:
        return f'({self.type.name}, {self.subdomain} -> {self.target})'


def parse_a_record(line: str) -> Record | None:
    """Parses a line of text into an A record.

    Args: a line of text to be parsed.

    Returns: a Record object corresponding to the parsed line or None if
             the line cannot be parsed.
    """
    result = re.fullmatch(RE_RECORD_A, line)
    if not result:
        return None
    return Record(
            type=Type.A,
            subdomain=result[1],
            target=result[2],
            id=0)


def parse_aaaa_record(line: str) -> Record | None:
    """Parses a line of text into an AAAA record.

    Args: a line of text to be parsed.

    Returns: a Record object corresponding to the parsed line or None if
             the line cannot be parsed.
    """
    result = re.fullmatch(RE_RECORD_AAAA, line)
    if not result:
        return None
    return Record(
            type=Type.AAAA,
            subdomain=result[1],
            target=result[2],
            id=0)


def parse_cname_record(line: str) -> Record | None:
    """Parses a line of text into a CNAME record.

    Args: a line of text to be parsed.

    Returns: a Record object corresponding to the parsed line or None if
             the line cannot be parsed.
    """
    result = re.fullmatch(RE_RECORD_CNAME, line)
    if not result:
        return None
    subdomain = result[1]
    target = result[2]
    # Catch mistake where CNAME points to an IP address.
    if any([re.fullmatch(RE_IPV4, subdomain), re.fullmatch(RE_IPV6, subdomain),
            re.fullmatch(RE_IPV4, target), re.fullmatch(RE_IPV6, target)]):
        return None
    return Record(
            type=Type.CNAME,
            subdomain=subdomain,
            target=target,
            id=0)


def parse_line(line: str) -> Record:
    record = parse_a_record(line)
    if record:
        return record
    record = parse_aaaa_record(line)
    if record:
        return record
    return parse_cname_record(line)


def fetch_records(record_type: Type, client: ovh.Client) -> Set[Record]:
    """Return a list of DNS record from OVH"""
    records = client.get(
            f'/domain/zone/{FLAGS.dns_zone}/record',
            fieldType=record_type.name)
    records = set()
    for record in records:
        d = client.get(f'/domain/zone/{FLAGS.dns_zone}/record/{record}')
        records.add(Record(
                type=record_type,
                subdomain=d['subDomain'],
                target=d['target'],
                id=record.id))
    return records


def add_record(record: Record, client: ovh.Client) -> int:
    """Adds a record to the DNS zone. Returns the OVH id for it."""
    logging.info('Creating record: %s', record)
    if _DRY_RUN.value:
        return 0

    record = client.post(f'/domain/zone/{FLAGS.dns_zone}/record',
                         fieldType=record.type.name,
                         subDomain=record.subdomain,
                         target=record.target)
    return record.id


def delete_record(record: Record, client: ovh.Client) -> None:
    """Deletes a record to the DNS zone."""
    logging.info('Deleting record: %s', record)
    if _DRY_RUN.value:
        return
    client.delete(f'/domain/zone/{FLAGS.dns_zone}/record/{record.id}')


def parse_input() -> Set[Record]:
    records = set()
    i = 0
    for line in fileinput.input():
        i += 1
        record = parse_line(line)
        if not record:
            logging.debug('Could not parse line %d, skipping: "%s"', i, line)
            continue
        logging.debug('Parsed line %d: %s', i, line)
        records.add(record)
    return records


def sort_records_by_type(records: Set[Record]) -> Dict[Type, Set[Record]]:
    records_by_type = {}
    for r in records:
        if r.type not in records_by_type:
            records_by_type[r.type] = set()
        records_by_type[r.type].add(r)
    return records_by_type


def reconcile(intent: Set[Record], current: Set[Record], client: ovh.Client):
    to_add = intent.difference(current)
    to_remove = current.difference(intent)
    for r in to_add:
        if r.type not in ALLOWED_TYPES:
            continue
        add_record(r, client)
    for r in to_remove:
        if r.type not in ALLOWED_TYPES:
            continue
        delete_record(r, client)


def main():
    """Updates the DNS zone."""


if __name__ == '__main__':
    app.run(main)
