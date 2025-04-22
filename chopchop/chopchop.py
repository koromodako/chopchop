"""Abstract Base Class"""

from collections.abc import Callable, Iterator
from dataclasses import dataclass
from hashlib import md5, sha1
from pathlib import Path
from platform import system
from sqlite3 import Connection, connect
from zlib import crc32

from lief import ELF, PE

from .logging import get_logger

_LOGGER = get_logger('chopchop')
_CREATE_STATEMENTS = (
    'CREATE TABLE IF NOT EXISTS digest (name TEXT PRIMARY KEY, md5 TEXT, sha1 TEXT, crc32 TEXT, custom TEXT)',
    'CREATE UNIQUE INDEX IF NOT EXISTS digest_md5 ON digest (md5)',
    'CREATE UNIQUE INDEX IF NOT EXISTS digest_sha1 ON digest (sha1)',
    'CREATE UNIQUE INDEX IF NOT EXISTS digest_crc32 ON digest (crc32)',
    'CREATE UNIQUE INDEX IF NOT EXISTS digest_custom ON digest (custom)',
)
_INSERT_STATEMENT = (
    'INSERT OR IGNORE INTO digest VALUES (:name, :md5, :sha1, :crc32, :custom)'
)
_ROWCOUNT_STATEMENT = 'SELECT count(*) FROM digest'
_SELECT_NAME_STATEMENT = (
    'SELECT name, md5, sha1, crc32, custom FROM digest WHERE name LIKE :name'
)
_SELECT_DIGEST_STATEMENT = 'SELECT name FROM digest WHERE md5 = :md5 OR sha1 = :sha1 OR crc32 = :crc32 OR custom = :custom'


def _pe_exports(item: Path) -> Iterator[str]:
    pef = PE.parse(item)
    if not pef:
        _LOGGER.warning("PE parsing failed for %s", item)
        return
    for function in pef.exported_functions:
        yield function.name


def _elf_exports(item: Path) -> Iterator[str]:
    elf = ELF.parse(item)
    if not elf:
        _LOGGER.warning("ELF parsing failed for %s", item)
        return
    for function in elf.exported_functions:
        yield function.name


_SYSTEM = system().lower()
_PARSING_STRATEGY = {
    'linux': _elf_exports,
    'windows': _pe_exports,
}


@dataclass(kw_only=True)
class Chopchop:
    """Chopchop"""

    database: Path
    custom_digest: Callable[[bytes], str] | None = None
    _connection: Connection | None = None

    @property
    def rowcount(self) -> int:
        """Row count"""
        row = next(self._connection.execute(_ROWCOUNT_STATEMENT))
        return row[0]

    def __enter__(self):
        _LOGGER.info("connecting to %s", self.database)
        self._connection = connect(self.database, autocommit=True)
        for stmt in _CREATE_STATEMENTS:
            self._connection.execute(stmt)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        _LOGGER.info("closing connection to %s", self.database)
        self._connection.close()
        self._connection = None

    def add(self, name: bytes | str):
        """Add name to digest table"""
        if isinstance(name, str):
            name = name.encode('utf-8')
        data = {
            'name': name.decode('utf-8'),
            'md5': md5(name).hexdigest(),
            'sha1': sha1(name).hexdigest(),
            'crc32': crc32(name).to_bytes(4, byteorder='little').hex(),
            'custom': None,
        }
        if self.custom_digest:
            data['custom'] = self.custom_digest(name)
        self._connection.execute(_INSERT_STATEMENT, data)

    def populate(self, directory: Path, globs: set[str]):
        """Find files matching glob recursively"""
        _LOGGER.info("populating using %s strategy", _SYSTEM)
        strategy = _PARSING_STRATEGY.get(_SYSTEM)
        if not strategy:
            _LOGGER.error("unsupported system: %s", _SYSTEM)
            return
        for glob in globs:
            for item in directory.rglob(glob):
                if not item.is_file():
                    continue
                count = 0
                # add item name
                self.add(item.name)
                self.add(item.name.upper())
                self.add(item.name.lower())
                self.add(item.name.lower().capitalize())
                count += 4
                # add item stem
                self.add(item.stem)
                self.add(item.stem.upper())
                self.add(item.stem.lower())
                self.add(item.stem.lower().capitalize())
                count += 4
                # add item exported functions
                for function_name in strategy(item):
                    self.add(function_name)
                    count += 1
                _LOGGER.info("added %d names from %s", count, item)

    def search_name(
        self, name: str
    ) -> Iterator[tuple[str, str, str, str, str | None]]:
        """Search for name associated with given digest"""
        _LOGGER.info("searching for name '%s'", name)
        data = {'name': name}
        for row in self._connection.execute(_SELECT_NAME_STATEMENT, data):
            yield tuple(row)

    def search_digest(self, digest: str | int) -> Iterator[str]:
        """Search for name associated with given digest"""
        _LOGGER.info("searching for digest '%s'", digest)
        size = 0
        if isinstance(digest, str) and digest.startswith('0x'):
            size = (len(digest) - 2) // 2
            if size not in {4, 8}:
                _LOGGER.error("invalid integer hex value: %s", digest)
                _LOGGER.error("expected a dword or qword value")
                return
            digest = int(digest, 0)
        if isinstance(digest, int):
            digest = digest.to_bytes(size, byteorder='little').hex()
        data = {
            'md5': digest,
            'sha1': digest,
            'crc32': digest,
            'custom': digest,
        }
        for row in self._connection.execute(_SELECT_DIGEST_STATEMENT, data):
            yield row[0]
