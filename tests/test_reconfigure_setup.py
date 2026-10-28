import grp
import os
from pathlib import Path
import pwd
import stat
import sys
import runpy
from unittest import mock
import subprocess
import tempfile
import unittest


ROOT = next(parent for parent in Path(__file__).resolve().parents if (parent / 'main.py').is_file())
HELPER = ROOT / 'scripts/setup-reconfigure-state'


class ReconfigureSetupTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name) / 'state'
        self.user = pwd.getpwuid(os.getuid()).pw_name
        self.group = grp.getgrgid(os.getgid()).gr_name

    def setup_state(self):
        return subprocess.run([sys.executable, str(HELPER), str(self.directory), self.user, self.group],
                              capture_output=True, text=True)

    def test_creates_private_state_and_preserves_keys_on_upgrade(self):
        result = self.setup_state()
        self.assertEqual(result.returncode, 0, result.stderr)
        state = self.directory / 'reconfigure.sqlite'
        self.assertEqual(stat.S_IMODE(state.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o770)
        self.assertEqual(state.stat().st_uid, os.getuid())
        state.write_bytes(b'existing-keys-and-replay-counter')
        state.chmod(0o644)
        other = self.directory / 'volatile.sqlite'
        other.write_bytes(b'existing-leases')
        other.chmod(0o640)
        result = self.setup_state()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(state.read_bytes(), b'existing-keys-and-replay-counter')
        self.assertEqual(stat.S_IMODE(state.stat().st_mode), 0o600)
        self.assertEqual(other.read_bytes(), b'existing-leases')
        self.assertEqual(stat.S_IMODE(other.stat().st_mode), 0o640)

    def test_refuses_symlink_without_modifying_target(self):
        self.directory.mkdir()
        target = Path(self.temporary.name) / 'outside'
        target.write_bytes(b'keep-me')
        target.chmod(0o644)
        (self.directory / 'reconfigure.sqlite').symlink_to(target)
        result = self.setup_state()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('regular file', result.stderr)
        self.assertEqual(target.read_bytes(), b'keep-me')
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o644)

    def test_refuses_non_regular_state(self):
        (self.directory / 'reconfigure.sqlite').mkdir(parents=True)
        self.assertNotEqual(self.setup_state().returncode, 0)
        self.assertTrue((self.directory / 'reconfigure.sqlite').is_dir())


    def test_path_replacement_cannot_change_an_outside_file(self):
        namespace = runpy.run_path(str(HELPER))
        original_chown = os.fchown
        outside = Path(self.temporary.name) / 'outside'
        outside.write_bytes(b'keep-outside-private-state')
        outside.chmod(0o644)
        attacked = []
        def replace_path(fd, uid, gid):
            if stat.S_ISREG(os.fstat(fd).st_mode) and not attacked:
                state = self.directory / 'reconfigure.sqlite'
                state.unlink()
                state.symlink_to(outside)
                attacked.append(True)
            return original_chown(fd, uid, gid)
        with mock.patch('os.fchown', side_effect=replace_path):
            namespace['prepare_state'](str(self.directory), self.user, self.group)
        self.assertTrue(attacked)
        self.assertEqual(outside.read_bytes(), b'keep-outside-private-state')
        self.assertEqual(stat.S_IMODE(outside.stat().st_mode), 0o644)
