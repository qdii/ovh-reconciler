#!/usr/bin/python3
"""Updates a DNS zone stored in OVH from a simple text file."""

from absl import app
from absl import flags


FLAGS = flags.FLAGS

flags.DEFINE_boolean(
    'verbose', False,
    'Increases the amount of information printed on the standard output')


def main():
    """Updates the DNS zone."""


if __name__ == '__main__':
    app.run(main)
