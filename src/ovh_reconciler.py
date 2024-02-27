#!/usr/bin/python3
"""Updates a DNS zone stored in OVH from a simple text file."""

import fileinput
import ovh
import re
import requests
from typing import NamedTuple, Set
from enum import Enum
from absl import app
from absl import flags
from absl import logging


FLAGS = flags.FLAGS

_APP_KEY = flags.DEFINE_string(
    'application_key', '',
    'A key given by OVH upon registering to api.ovh.com')

_APP_SECRET = flags.DEFINE_string(
    'application_secret', '',
    'A secret given by OVH upon registering to api.ovh.com')

_CONSUMER_KEY = flags.DEFINE_string(
    'consumer_key', '',
    'A key given by OVH upon registering to api.ovh.com. It is attached to '
    'your account')

_ENDPOINT = flags.DEFINE_string(
    'endpoint', 'ovh-eu',
    'The OVH API endpoint to use.')

_INPUT = flags.DEFINE_string(
    'input', '-',
    'The file containing the DNS zones to process. If "-" is passed, then '
    'the standard input is read')

_DNS_ZONE = flags.DEFINE_string(
    'dns_zone', '',
    'The DNS zone to administer. For instance "dodges.it".')

_DRY_RUN = flags.DEFINE_bool(
    'dry_run', False,
    'If True, no records are created or deleted.')

_DEFAULT_TTL = flags.DEFINE_integer(
    'default_ttl', 0,
    'The default ttl to use if not in the indicated in the record row.')

_ENABLE_PUBLIC_IP = flags.DEFINE_boolean(
    'enable_public_ip', False,
    'If set to true, instead of setting an IP address in A records, '
    'the token {PUBLIC_IP} can be used. The script will query ifconfig.me '
    'and replace the token with the IP returned from it.')


# TODO: This accepts invalid IPs, such as 999.999.999.999. Make it stricter.
RE_IPV4 = r'(?P<ipv4>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
RE_IPV6 = r'(?P<ipv6>([a-f0-9:]+:+)+[a-f0-9]+)'
# This regex matches either a double-quote delimited string, or the same
# but wrapped inside parenthesis.
RE_TXT = r'(?:"(?P<txt1>[^"]*)"|\(\s*"(?P<txt2>[^"]*)"\s*\))'
RE_TTL = r'(?P<ttl>[0-9]*)'
RE_SUBDOMAIN = r'(?P<subdomain>[-.@|a-zA-Z0-9_]*)'
RE_TARGET = r'(?P<target>[-.@|a-zA-Z0-9_]*)'
RE_RECORD_A = r'^\s*' + RE_SUBDOMAIN + r'\s*' + RE_TTL + r'\s*IN\s+A\s+' + RE_IPV4 + r'\s*$'
RE_RECORD_AAAA = r'^\s*' + RE_SUBDOMAIN + r'\s*' + RE_TTL + r'\s*IN\s+AAAA\s+' + RE_IPV6 + r'\s*$'
RE_RECORD_CNAME = r'^\s*' + RE_SUBDOMAIN + r'\s*' + RE_TTL + r'\s+IN\s+CNAME\s+' + RE_TARGET + r'\s*$'  # pylint: disable=line-too-long
RE_RECORD_TXT = r'^\s*' + RE_SUBDOMAIN + r'\s*' + RE_TTL + r'\s+IN\s+TXT\s+' + RE_TXT + r'\s*$'


class CannotRetrievePublicIPError(Exception):
    pass

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
    Type.TXT,
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

    # The time-to-live of the DNS record. 0 means no caching. None means the
    # TTL is not send to OVH API.
    ttl: int | None

    def __str__(self) -> str:
        """A printable representation of the object."""
        ttl = f' ({self.ttl})' if self.ttl else ''
        return f'({self.type.name}, {self.subdomain}{ttl} -> {self.target})'

    def __eq__(self, other):
        """Whether two objects are the same. Needed when comparing sets."""
        if self.type != other.type:
            return False
        if self.subdomain != other.subdomain:
            return False
        if self.target != other.target:
            return False
        if self.ttl and other.ttl and self.ttl != other.ttl:
            return False
        return True

    def __hash__(self):
        """Whether two objects are the same. Needed when comparing sets."""
        return hash((self.type, self.subdomain, self.target, self.ttl or 0))


def parse_a_record(line: str) -> Record | None:
    """Parses a line of text into an A record.

    Args: a line of text to be parsed.

    Returns: a Record object corresponding to the parsed line or None if
             the line cannot be parsed.
    """
    result = re.fullmatch(RE_RECORD_A, line, re.MULTILINE)
    if not result:
        return None
    ttl = result.group('ttl') or _DEFAULT_TTL.value
    if ttl:
        ttl = int(ttl)
    return Record(
            type=Type.A,
            subdomain=result.group('subdomain'),
            target=result.group('ipv4'),
            ttl=ttl,
            id=0)


def parse_aaaa_record(line: str) -> Record | None:
    """Parses a line of text into an AAAA record.

    Args: a line of text to be parsed.

    Returns: a Record object corresponding to the parsed line or None if
             the line cannot be parsed.
    """
    result = re.fullmatch(RE_RECORD_AAAA, line, re.MULTILINE)
    if not result:
        return None
    ttl = result.group('ttl') or _DEFAULT_TTL.value
    if ttl:
        ttl = int(ttl)
    return Record(
            type=Type.AAAA,
            subdomain=result.group('subdomain'),
            target=result.group('ipv6'),
            ttl=ttl,
            id=0)


def parse_txt_record(line: str) -> Record | None:
    """Parses a line of text into an TXT record.

    Args: a line of text to be parsed.

    Returns: a Record object corresponding to the parsed line or None if
             the line cannot be parsed.
    """
    result = re.fullmatch(RE_RECORD_TXT, line, re.MULTILINE)
    if not result:
        return None
    ttl = result.group('ttl') or _DEFAULT_TTL.value
    if ttl:
        ttl = int(ttl)
    target = (result.group('txt1') or '') + (result.group('txt2') or '')
    return Record(
            type=Type.TXT,
            subdomain=result.group('subdomain'),
            target=target,
            ttl=ttl,
            id=0)


def parse_cname_record(line: str) -> Record | None:
    """Parses a line of text into a CNAME record.

    Args: a line of text to be parsed.

    Returns: a Record object corresponding to the parsed line or None if
             the line cannot be parsed.
    """
    result = re.fullmatch(RE_RECORD_CNAME, line, re.MULTILINE)
    if not result:
        return None
    subdomain = result.group('subdomain')
    target = result.group('target')
    ttl = result.group('ttl') or _DEFAULT_TTL.value
    if ttl:
        ttl = int(ttl)
    # Catch mistake where CNAME points to an IP address.
    if any([re.fullmatch(RE_IPV4, subdomain, re.M),
            re.fullmatch(RE_IPV6, subdomain, re.M),
            re.fullmatch(RE_IPV4, target, re.M),
            re.fullmatch(RE_IPV6, target, re.M)]):
        return None
    return Record(
            type=Type.CNAME,
            subdomain=subdomain,
            target=target,
            ttl=ttl,
            id=0)


def parse_line(line: str, my_ip: str | None = None) -> Record:
    if my_ip:
        line = line.replace('{PUBLIC_IP}', my_ip)

    record = parse_a_record(line)
    if record:
        return record
    record = parse_aaaa_record(line)
    if record:
        return record
    record = parse_txt_record(line)
    if record:
        return record
    return parse_cname_record(line)


def fetch_records(record_type: Type, client: ovh.Client) -> Set[Record]:
    """Return a list of DNS record from OVH"""
    record_ids = client.get(
            f'/domain/zone/{_DNS_ZONE.value}/record',
            fieldType=record_type.name)
    logging.info('Fetched %d records of type %s for zone %s.',
                  len(record_ids), record_type.name, _DNS_ZONE.value)
    records = set()
    for id in record_ids:
        d = client.get(f'/domain/zone/{_DNS_ZONE.value}/record/{id}')
        r = Record(
                type=record_type,
                subdomain=d['subDomain'],
                target=d['target'],
                ttl=d['ttl'],
                id=id)
        logging.debug('Fetched record [%d]: %s', id, r)
        records.add(r)
    return records


def add_record(record: Record, client: ovh.Client) -> int:
    """Adds a record to the DNS zone. Returns the OVH id for it."""
    logging.info('Creating record: %s', record)
    if _DRY_RUN.value:
        return 0

    record = client.post(f'/domain/zone/{_DNS_ZONE.value}/record',
                         fieldType=record.type.name,
                         subDomain=record.subdomain,
                         ttl=record.ttl,
                         target=record.target)
    return record['id']


def delete_record(record: Record, client: ovh.Client) -> None:
    """Deletes a record to the DNS zone."""
    logging.info('Deleting record: %s', record)
    if _DRY_RUN.value:
        return
    client.delete(f'/domain/zone/{_DNS_ZONE.value}/record/{record.id}')


def parse_input() -> Set[Record]:
    my_ip = public_ip() if _ENABLE_PUBLIC_IP.value else None
    records = set()
    i = 0
    records_per_type = {}
    for type in ALLOWED_TYPES:
        records_per_type[type] = []

    # Parsed each line of the file.
    with fileinput.FileInput(files=_INPUT.value) as f:
        for line in f:
            i += 1
            record = parse_line(line, my_ip)
            if not record:
                logging.debug('Could not parse line %d, skipping: "%s"', i, line)
                continue
            logging.debug('Parsed line %d: %s', i, record)
            records.add(record)
            records_per_type[record.type].append(record)

    # Print out debug information.
    for type in ALLOWED_TYPES:
        logging.info('Parsed %d records of type %s.',
                     len(records_per_type[type]), type.name)

        for r in records_per_type[type]:
            logging.debug('Parsed record: %s', r)

    return records


def get_public_ip_from_ifconfig_me() -> str:
    try:
        response = requests.get('https://ifconfig.me')
        if response.status_code == 200:
            return response.text.strip()
        else:
            raise CannotRetrievePublicIPError('ifconfig.me did not return 200')
    except requests.exceptions.RequestException as e:
        raise CannotRetrievePublicIPError from e


def public_ip() -> str | None:
    try:
        my_ip = get_public_ip_from_ifconfig_me()
    except CannotRetrievePublicIPError as e:
        logging.warning('Cannot retrieve public IP from ifconfig.me, '
                        'records with {PUBLIC_IP} will not be added: %s.', e)
        my_ip = None
    return my_ip


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


def apply(client: ovh.Client):
    if _DRY_RUN.value:
        return
    logging.info('Applying modifications.')
    client.post(f'/domain/zone/{_DNS_ZONE.value}/refresh')


def main(unused_argv):
    client = ovh.Client(
            endpoint=_ENDPOINT.value,
            application_key=_APP_KEY.value,
            application_secret=_APP_SECRET.value,
            consumer_key=_CONSUMER_KEY.value)
    logging.info('Parsing input file')
    intent = parse_input()
    current = set()
    for type in ALLOWED_TYPES:
        logging.info('Fetching existing records of type %s', type.name)
        current = current.union(fetch_records(type, client))
    logging.info('Reconciling intent and reality')
    reconcile(intent, current, client)
    apply(client)


if __name__ == '__main__':
    app.run(main)
