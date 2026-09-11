"""PID-file lifecycle helpers for dhcpy6d."""

import atexit
import os
from pathlib import Path


def write_pid_file(path):
    """Write the current daemon PID and remove the file at clean exit."""
    if not path:
        return
    pid_file = Path(path)
    pid_file.parent.mkdir(parents=True, exist_ok=True)
    pid_file.write_text(f'{os.getpid()}\n')
    atexit.register(lambda: pid_file.unlink(missing_ok=True))
