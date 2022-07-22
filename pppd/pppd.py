import os
import sys

import click
import crayons

from .validator import Validator
from .utils import print_bold


@click.group()
@click.version_option("0.0.1")
def main():
    """A Dependency Version Pinning Enforecement tool"""
    pass

@main.command()
@click.argument('path', required=False)
def test(**kwargs):
    path = kwargs['path']
    _test(path)

def _test(path: str):
    """Search through CVE Database for vulnerabilities"""

    validator = Validator(path)
    validator.discover()
    validator.validate()

    if validator.vulnerable_files:
        print_bold(crayons.red(f'Issues Found!'))
        print('One or more dependency definitions are not pinned to an exact version.\n')

    for file_name in validator.vulnerable_files:
        scan_type = validator.vulnerable_files[file_name]['scan_type']
        print_bold(f'{file_name} ({scan_type})')
        for issue in validator.vulnerable_files[file_name]['issues']:
            dependency = issue['dependency']
            print(crayons.red(f'    ✘ {dependency}'))

    if validator.vulnerable_files:
        exit(1)

if __name__ == '__main__':
    args = sys.argv
    main()
