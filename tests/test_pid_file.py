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


class SystemdSupervisionTest(unittest.TestCase):
    def test_unit_uses_runtime_pid_file_and_restarts(self):
        with open('debian/dhcpy6d.service') as handle:
            service = handle.read()
        self.assertIn('Type=exec', service)
        self.assertIn('RuntimeDirectory=dhcpy6d', service)
        self.assertIn('PIDFile=/run/dhcpy6d/dhcpy6d.pid', service)
        self.assertIn('Restart=on-failure', service)
        self.assertIn('--pid-file /run/dhcpy6d/dhcpy6d.pid', service)
