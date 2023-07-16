#!/usr/bin/python3
"""Updates a DNS zone stored in OVH from a simple text file."""

from enum import Enum
from absl import app
from absl import flags
from typing import NamedTuple
import re


FLAGS = flags.FLAGS

flags.DEFINE_boolean(
    'verbose', False,
    'Increases the amount of information printed on the standard output')


# TODO: This accepts invalid IPs, such as 999.999.999.999. Make it stricter.
RE_IPV4 = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
RE_IPV6 = r'(([a-f0-9:]+:+)+[a-f0-9]+)'
RE_SUBDOMAIN = r'([-.a-zA-Z0-9_]+)'
RE_RECORD_A = r'\s*' + RE_SUBDOMAIN + r'\s+' + 'A' + r'\s+' + RE_IPV4 + r'\s*'
RE_RECORD_AAAA = r'\s*' + RE_SUBDOMAIN + r'\s+IN\s+AAAA\s+' + RE_IPV6 + r'\s*'


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
            target=result[2])


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
            target=result[2])


def parse_line(line: str) -> Record:
    record = parse_a_record(line)
    if record:
        return record
    return parse_aaaa_record(line)


def main():
    """Updates the DNS zone."""


if __name__ == '__main__':
    app.run(main)
