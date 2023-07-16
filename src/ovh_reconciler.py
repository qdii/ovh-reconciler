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
RE_SUBDOMAIN = r'([-.a-zA-Z0-9_]+)'
RE_RECORD_A = RE_SUBDOMAIN + r'\s+' + 'A' + r'\s+' + RE_IPV4


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


def parse_line(line: str) -> Record:
    """Parses a line of text into a valid object.

    Returns: a Record object corresponding to the parsed line.
    Raises:
      ValueError if the input line cannot be parsed.
    """
    if not re.fullmatch(RE_RECORD_A, line):
        raise ValueError('not a A record')
    return Record(
            type=Type.A,
            subdomain='foo.dodges.it',
            target='10.0.0.1')


def main():
    """Updates the DNS zone."""


if __name__ == '__main__':
    app.run(main)
