"""Importing this package registers every check via the @register decorator."""
from . import (  # noqa: F401
    antivirus,
    browser,
    filesystem,
    keylogger,
    malware,
    network,
    persistence,
    processes,
    ssh,
)
