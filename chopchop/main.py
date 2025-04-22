#!/usr/bin/env python3
"""Chopchop entrypoint"""
from argparse import ArgumentParser, Namespace
from json import dumps
from pathlib import Path

from .__version__ import version
from .chopchop import Chopchop
from .logging import get_logger

_LOGGER = get_logger('main')


def _populate(chopchop: Chopchop, args: Namespace):
    chopchop.populate(args.directory, set(args.globs))


def _rowcount(chopchop: Chopchop, args: Namespace):
    rowcount = chopchop.rowcount
    if args.json:
        print(dumps({'rowcount': rowcount}))
    else:
        print(rowcount)


def _search_name(chopchop: Chopchop, args: Namespace):
    for candidate in args.names:
        for name, md5, sha1, crc32, custom in chopchop.search_name(candidate):
            if args.json:
                print(
                    dumps(
                        {
                            'md5': md5,
                            'sha1': sha1,
                            'crc32': crc32,
                            'custom': custom,
                            'name': name,
                        }
                    )
                )
            else:
                print(f"{md5} {sha1} {crc32} {custom} {name}")


def _search_digest(chopchop: Chopchop, args: Namespace):
    for digest in args.digests:
        for name in chopchop.search_digest(digest):
            if args.json:
                print(dumps({'digest': digest, 'name': name}))
            else:
                print(f"{digest} {name}")


def _parse_args():
    parser = ArgumentParser(description=f"Chopchop {version}")
    parser.add_argument(
        '--json',
        action='store_true',
        help="Use JSON output format",
    )
    parser.add_argument(
        '--reset',
        action='store_true',
        help="Remove chopchop.db before processing command",
    )
    parser.add_argument(
        '--database',
        type=Path,
        default=Path('chopchop.db'),
        help="Database file",
    )
    cmd = parser.add_subparsers(dest='cmd', required=True, help="Command")
    populate = cmd.add_parser('populate', help="Populate database")
    populate.add_argument(
        'directory',
        type=Path,
        help="Directory to scan recursively using given globs",
    )
    populate.add_argument(
        'globs',
        nargs='+',
        metavar='glob',
        help="Globs to match in given directory",
    )
    populate.set_defaults(func=_populate)
    rowcount = cmd.add_parser('rowcount', help="Display row count")
    rowcount.set_defaults(func=_rowcount)
    search = cmd.add_parser('search', help="Search for item")
    item = search.add_subparsers(
        dest='item', required=True, help="Item to search"
    )
    name = item.add_parser(
        'name', help="Search for digest associated with given names"
    )
    name.add_argument(
        'names',
        nargs='+',
        metavar='NAME',
        help="Name to search in the database",
    )
    name.set_defaults(func=_search_name)
    digest = item.add_parser(
        'digest', help="Search for names associated with given digests"
    )
    digest.add_argument(
        'digests',
        nargs='+',
        metavar='DIGEST',
        help="Digest to search in the database",
    )
    digest.set_defaults(func=_search_digest)
    return parser.parse_args()


def app():
    """Chopchop CLI entrypoint"""
    _LOGGER.info("chopchop %s", version)
    args = _parse_args()
    if args.reset and args.database.is_file():
        args.database.unlink()
    with Chopchop(database=args.database) as chopchop:
        args.func(chopchop, args)
