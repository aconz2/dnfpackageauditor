#!/usr/bin/env python3

import dnf
import itertools
from collections import defaultdict
import argparse
import sys
from operator import itemgetter

base = dnf.Base()
base.fill_sack()

def get_installed(prefix):
    package_map = defaultdict(list)
    installed_files = set()

    for package in base.sack.query().installed():
        for file in package.files:
            if file.startswith(prefix):
                installed_files.add(file)
                package_map[file].append(package.name)

    return package_map, installed_files

if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('--prefix', default='')
    args = parser.parse_args()

    package_map, installed_files = get_installed(args.prefix)
    used = set(map(str.strip, sys.stdin.read()))

    installed_not_used = installed_files - used
    used_not_installed = used - installed_files

    out_installed_not_used = sorted(
        ((','.join(package_map[file]), file) for file in installed_not_used),
        key=itemgetter(0),
    )
    packages_not_used = set(itertools.chain.from_iterable(
        package_map[file] for file in installed_not_used
    ))

    print('--Packages Not Used--')
    print('\n'.join(sorted(packages_not_used)))

    print('--Installed Not Used--')
    for a, b in out_installed_not_used:
        print(f'{a:<30} {b}')
    print()

    print('--Used Not Installed--')
    for file in used_not_installed:
        if file.startswith(args.prefix):
            print(used_not_installed)
