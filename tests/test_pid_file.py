import os
import tempfile
import unittest

from dhcpy6d.pidfile import write_pid_file


class PidFileTest(unittest.TestCase):
    def test_writes_current_pid(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'run', 'dhcpy6d.pid')
            write_pid_file(path)
            with open(path) as handle:
                self.assertEqual(handle.read(), f'{os.getpid()}\n')

    def test_empty_path_is_ignored(self):
        self.assertIsNone(write_pid_file(None))

