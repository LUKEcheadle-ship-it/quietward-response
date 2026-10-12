"""Private source-level regression suite. Windows API tests are mocked, not native."""
from __future__ import annotations

import copy
import ctypes
import importlib.util
import json
import os
import platform
import select
import signal
import subprocess
import sys
import tempfile
import unittest
from ctypes import wintypes
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
import evidence_store as evidence
import process_containment as containment
import response_agent_diagnostics as diagnostics

KEY = b"synthetic-test-key-never-for-production" * 2
ROW = {"pid": 4000001, "parent_pid": 4000000, "image": "sample-worker"}
BOOT = "10000000-0000-0000-0000-000000000001"
PROCESS = {**ROW, "start_marker": "12345"}


class EvidenceAuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.enterContext(patch.object(evidence, "process_start_marker", return_value="12345"))
        self.enterContext(patch.object(evidence, "_boot_identity", return_value=BOOT))
        self.store = evidence.EvidenceStore(self.root, KEY)
        self.handle = self.store.record_process(ROW)

    def mutate(self, fn):
        data = json.loads(self.store.path.read_text())
        fn(data["entries"][self.handle])
        self.store.path.write_text(json.dumps(data))

    def test_signed_round_trip(self):
        result = self.store.resolve_process(self.handle, [ROW])
        self.assertEqual(result["pid"], ROW["pid"])
        self.assertEqual(result["start_marker"], "12345")

    def test_target_rewrite_rejected(self):
        self.mutate(lambda r: r["locator"].update(pid=4000002))
        with self.assertRaisesRegex(evidence.EvidenceStoreError, "authentication"):
            self.store.resolve_process(self.handle, [{**ROW, "pid": 4000002}])

    def test_expiry_rewrite_rejected(self):
        self.mutate(lambda r: r.update(expires_at=(datetime.now(timezone.utc)+timedelta(days=2)).isoformat()))
        with self.assertRaisesRegex(evidence.EvidenceStoreError, "authentication"):
            self.store.resolve_process(self.handle, [ROW])

    def test_wrong_key_rejected(self):
        with self.assertRaisesRegex(evidence.EvidenceStoreError, "authentication"):
            evidence.EvidenceStore(self.root, b"another-synthetic-key" * 3).resolve_process(self.handle, [ROW])

    def test_legacy_unsigned_rejected_until_recollected(self):
        self.mutate(lambda r: r.pop("record_hmac_sha256"))
        with self.assertRaisesRegex(evidence.EvidenceStoreError, "fresh triage"):
            self.store.resolve_process(self.handle, [ROW])
        self.assertEqual(self.store.record_process(ROW), self.handle)
        self.assertEqual(self.store.resolve_process(self.handle, [ROW])["pid"], ROW["pid"])

    def test_boot_change_rejected(self):
        with patch.object(evidence, "_boot_identity", return_value=BOOT[:-1]+"2"):
            with self.assertRaisesRegex(evidence.EvidenceStoreError, "reboot"):
                self.store.resolve_process(self.handle, [ROW])

    def test_unavailable_process_marker_rejected(self):
        with patch.object(evidence, "process_start_marker", return_value=None):
            with self.assertRaisesRegex(evidence.EvidenceStoreError, "instance changed"):
                self.store.resolve_process(self.handle, [ROW])

    def test_pid_reuse_rejected(self):
        with patch.object(evidence, "process_start_marker", return_value="98765"):
            with self.assertRaisesRegex(evidence.EvidenceStoreError, "instance changed"):
                self.store.resolve_process(self.handle, [ROW])

    def test_changed_parent_rejected(self):
        with self.assertRaisesRegex(evidence.EvidenceStoreError, "parent identity"):
            self.store.resolve_process(self.handle, [{**ROW, "parent_pid": 17}])

    def test_changed_image_rejected(self):
        with self.assertRaisesRegex(evidence.EvidenceStoreError, "image identity"):
            self.store.resolve_process(self.handle, [{**ROW, "image": "another-worker"}])

    def test_ambiguous_inventory_rejected(self):
        with self.assertRaisesRegex(evidence.EvidenceStoreError, "ambiguous"):
            self.store.resolve_process(self.handle, [ROW, ROW])

    def test_malformed_inventory_rows_ignored_without_crash(self):
        result = self.store.resolve_process(self.handle, [{"pid": "bad"}, {"pid": True}, None, ROW])
        self.assertEqual(result["pid"], ROW["pid"])

    def test_invalid_pid_not_coerced_into_target(self):
        for pid in (True, "7", 2.5, None, -1, 0):
            with self.subTest(pid=pid):
                self.assertIsNone(self.store.record_process({**ROW, "pid": pid}))

    @unittest.skipUnless(os.name == "posix", "POSIX symlink test; Windows reparse qualification is separate")
    def test_predictable_temporary_symlink_does_not_overwrite_target(self):
        other = self.root / "unrelated.txt"
        other.write_text("PRESERVE")
        self.store.path.with_name(self.store.path.name+".tmp").symlink_to(other)
        self.store.record_process(ROW)
        self.assertEqual(other.read_text(), "PRESERVE")

    @unittest.skipUnless(os.name == "posix", "POSIX symlink test; Windows reparse qualification is separate")
    def test_store_symlink_rejected(self):
        other = self.root / "actual.json"
        self.store.path.rename(other)
        self.store.path.symlink_to(other)
        with self.assertRaisesRegex(evidence.EvidenceStoreError, "symlink"):
            self.store.resolve_process(self.handle, [ROW])

    def test_oversized_store_rejected(self):
        with patch.object(evidence, "MAX_EVIDENCE_BYTES", 30):
            with self.assertRaisesRegex(evidence.EvidenceStoreError, "size limit"):
                self.store.resolve_process(self.handle, [ROW])

    def test_expired_signed_record_rejected(self):
        data = self.store._load()
        record = data["entries"][self.handle]
        now = datetime.now(timezone.utc)
        record["created_at"] = (now-timedelta(minutes=40)).isoformat()
        record["expires_at"] = (now-timedelta(minutes=10)).isoformat()
        record["record_hmac_sha256"] = self.store._record_signature(self.handle, record)
        self.store.path.write_text(json.dumps(data))
        with self.assertRaisesRegex(evidence.EvidenceStoreError, "expired"):
            self.store.resolve_process(self.handle, [ROW])

    @unittest.skipUnless(hasattr(os, "mkfifo"), "POSIX FIFO test")
    def test_nonregular_store_refused_without_waiting_for_a_writer(self):
        self.store.path.unlink()
        os.mkfifo(self.store.path)
        with self.assertRaisesRegex(evidence.EvidenceStoreError, "regular file"):
            self.store.resolve_process(self.handle, [ROW])

    def test_missing_inventory_preserves_existing_stale_handle_contract(self):
        with self.assertRaisesRegex(evidence.EvidenceStoreError, "no longer running"):
            self.store.resolve_process(self.handle, [])

    def test_bad_timestamp_is_domain_error(self):
        with self.assertRaises(evidence.EvidenceStoreError):
            evidence._parse_time("not-a-timestamp")


class LinuxStableReferenceTests(unittest.TestCase):
    def setUp(self):
        self.opener = self.enterContext(patch.object(containment.os, "pidfd_open", return_value=998, create=True))
        self.sender = self.enterContext(patch.object(containment.signal, "pidfd_send_signal", create=True))
        self.closer = self.enterContext(patch.object(containment.os, "close"))
        self.identity = self.enterContext(patch.object(containment, "_linux_identity_matches", return_value=True))
        self.exited = self.enterContext(patch.object(containment, "_pidfd_exited", side_effect=[False, True]))
        self.kill = self.enterContext(patch.object(containment.os, "kill", side_effect=AssertionError("numeric PID signalling forbidden")))

    def test_success_signals_stable_reference(self):
        self.assertTrue(containment._terminate_linux(PROCESS))
        self.sender.assert_called_once_with(998, signal.SIGTERM, None, 0)
        self.closer.assert_called_once_with(998)
        self.kill.assert_not_called()

    def test_pid_reuse_between_resolution_and_open_refuses_signal(self):
        self.identity.return_value = False
        with self.assertRaisesRegex(containment.ProcessContainmentError, "identity changed"):
            containment._terminate_linux(PROCESS)
        self.sender.assert_not_called()
        self.closer.assert_called_once_with(998)

    def test_missing_pidfd_support_never_falls_back_to_kill(self):
        with patch.object(containment.os, "pidfd_open", None):
            with self.assertRaisesRegex(containment.ProcessContainmentError, "pidfd support"):
                containment._terminate_linux(PROCESS)
        self.sender.assert_not_called()
        self.kill.assert_not_called()

    def test_no_false_success_on_exit_timeout(self):
        self.exited.side_effect = [False, False]
        with self.assertRaisesRegex(containment.ProcessContainmentError, "not confirmed"):
            containment._terminate_linux(PROCESS)
        self.closer.assert_called_once_with(998)

    def test_permission_error_not_treated_as_exit(self):
        self.sender.side_effect = PermissionError("denied")
        with self.assertRaises(containment.ProcessContainmentError):
            containment._terminate_linux(PROCESS)
        self.closer.assert_called_once_with(998)

    def test_process_already_exited_is_not_a_mutation_success(self):
        self.exited.side_effect = [True]
        with self.assertRaisesRegex(containment.ProcessContainmentError, "already exited"):
            containment._terminate_linux(PROCESS)
        self.sender.assert_not_called()

    def test_open_failure_does_not_close_unowned_descriptor(self):
        self.opener.side_effect = ProcessLookupError("gone")
        with self.assertRaises(containment.ProcessContainmentError):
            containment._terminate_linux(PROCESS)
        self.closer.assert_not_called()


class WindowsStableReferenceTests(unittest.TestCase):
    """API mocks test call ordering/denials. They do NOT qualify native Windows."""
    def setUp(self):
        self.api = Mock()
        self.api.OpenProcess.return_value = 77
        self.api.TerminateProcess.return_value = True
        self.api.WaitForSingleObject.side_effect = [0x102, 0]
        self.marker = 12345
        self.image = r"C:\Program Files\Example\sample-worker.exe"
        self.critical = False
        self.times_ok = self.image_ok = self.critical_ok = True
        self.process = {**PROCESS, "image": "sample-worker.exe"}
        def times(h, created, *unused):
            ctypes.cast(created, ctypes.POINTER(wintypes.FILETIME)).contents.dwLowDateTime = self.marker
            return self.times_ok
        def image(h, flags, buf, size):
            buf.value = self.image
            return self.image_ok
        def critical(h, out):
            ctypes.cast(out, ctypes.POINTER(wintypes.BOOL)).contents.value = self.critical
            return self.critical_ok
        self.api.GetProcessTimes.side_effect = times
        self.api.QueryFullProcessImageNameW.side_effect = image
        self.api.IsProcessCritical.side_effect = critical
        self.enterContext(patch.object(containment.os, "name", "nt"))
        self.enterContext(patch.object(containment, "_windows_api", return_value=self.api))

    def test_one_handle_used_for_identity_termination_and_wait(self):
        self.assertTrue(containment._terminate_windows(self.process))
        self.api.OpenProcess.assert_called_once_with(0x101001, False, PROCESS["pid"])
        self.api.TerminateProcess.assert_called_once_with(77, 1)
        for name in ["GetProcessTimes", "QueryFullProcessImageNameW", "IsProcessCritical", "CloseHandle"]:
            self.assertEqual(getattr(self.api, name).call_args.args[0], 77)
        names = [c[0] for c in self.api.method_calls]
        self.assertLess(names.index("IsProcessCritical"), names.index("TerminateProcess"))

    def test_reused_pid_refused_before_mutation(self):
        self.marker = 99999
        with self.assertRaisesRegex(containment.ProcessContainmentError, "instance changed"):
            containment._terminate_windows(self.process)
        self.api.TerminateProcess.assert_not_called()
        self.api.CloseHandle.assert_called_once_with(77)

    def test_critical_process_refused(self):
        self.critical = True
        with self.assertRaisesRegex(containment.ProcessContainmentError, "critical process"):
            containment._terminate_windows(self.process)
        self.api.TerminateProcess.assert_not_called()

    def test_unknown_critical_status_refused(self):
        self.critical_ok = False
        with self.assertRaisesRegex(containment.ProcessContainmentError, "critical-process status"):
            containment._terminate_windows(self.process)
        self.api.TerminateProcess.assert_not_called()

    def test_unknown_creation_time_refused(self):
        self.times_ok = False
        with self.assertRaisesRegex(containment.ProcessContainmentError, "creation identity"):
            containment._terminate_windows(self.process)
        self.api.TerminateProcess.assert_not_called()

    def test_changed_image_refused(self):
        self.image = r"C:\Different\other.exe"
        with self.assertRaisesRegex(containment.ProcessContainmentError, "image identity changed"):
            containment._terminate_windows(self.process)
        self.api.TerminateProcess.assert_not_called()

    def test_unknown_image_refused(self):
        self.image_ok = False
        with self.assertRaisesRegex(containment.ProcessContainmentError, "image identity is unavailable"):
            containment._terminate_windows(self.process)
        self.api.TerminateProcess.assert_not_called()

    def test_timeout_cannot_report_success(self):
        self.api.WaitForSingleObject.side_effect = [0x102, 0x102]
        with self.assertRaisesRegex(containment.ProcessContainmentError, "not confirmed"):
            containment._terminate_windows(self.process)
        self.api.CloseHandle.assert_called_once_with(77)

    def test_already_dead_handle_not_terminated(self):
        self.api.WaitForSingleObject.side_effect = [0]
        with self.assertRaisesRegex(containment.ProcessContainmentError, "not confirmed active"):
            containment._terminate_windows(self.process)
        self.api.TerminateProcess.assert_not_called()


class ProtectionTests(unittest.TestCase):
    def test_self_parent_and_critical_pids_protected(self):
        for pid in [0, 1, 2, os.getpid(), os.getppid()]:
            with self.subTest(pid=pid):
                self.assertIsNotNone(containment._protected_reason({**PROCESS, "pid": pid}))

    def test_system_images_protected_case_insensitively(self):
        for image in containment._PROTECTED_IMAGES:
            with self.subTest(image=image):
                self.assertIsNotNone(containment._protected_reason({**PROCESS, "image": image.upper()}))


@unittest.skipUnless(platform.system() == "Linux" and hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"), "native Linux pidfd test")
class NativeChildTests(unittest.TestCase):
    def test_real_child_tamper_refusal_then_exact_process_containment(self):
        # The ONLY mutation target is the child created by this test. Never accept
        # an external PID, user process, service, or remote endpoint as a fixture.
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(20)"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            with tempfile.TemporaryDirectory() as tmp:
                row = diagnostics._linux_process(child.pid)
                self.assertIsNotNone(row)
                self.assertEqual(row["parent_pid"], os.getpid())
                store = evidence.EvidenceStore(Path(tmp), KEY)
                handle = store.record_process(row)
                original = store.path.read_bytes()
                data = json.loads(original)
                data["entries"][handle]["locator"]["pid"] = os.getpid()
                store.path.write_text(json.dumps(data))
                with self.assertRaises(containment.ProcessContainmentError):
                    containment.terminate_evidence_process(Path(tmp), KEY, handle)
                self.assertIsNone(child.poll())
                store.path.write_bytes(original)
                result = containment.terminate_evidence_process(Path(tmp), KEY, handle)
                self.assertTrue(result["stable_process_reference_used"])
                self.assertTrue(result["confirmed_original_process_exited"])
                self.assertEqual(result["process"]["pid"], child.pid)
                self.assertIsNotNone(child.wait(timeout=3))
        finally:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
