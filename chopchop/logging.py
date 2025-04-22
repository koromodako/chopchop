"""chopchop logging module"""

from logging import Logger, basicConfig, getLogger
from os import getenv

from rich.console import Console
from rich.logging import RichHandler

CHOPCHOP_DEBUG = bool(getenv('CHOPCHOP_DEBUG'))


basicConfig(
    level='DEBUG' if CHOPCHOP_DEBUG else 'INFO',
    format='%(message)s',
    datefmt='%Y-%m-%dT%H:%M:%S',
    handlers=[RichHandler(console=Console(stderr=True))],
)


def get_logger(name: str) -> Logger:
    """Retrieve logger for given name"""
    name = '.'.join(['chopchop', name])
    return getLogger(name)
