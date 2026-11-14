import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

import fixtures  # noqa: E402
from tailcat_addr_exposure.scan import scan_paths  # noqa: E402

BIN = os.path.join(ROOT, "bin", "tailcat-addr-exposure")
EXAMPLES = os.path.join(ROOT, "examples", "in")


def run(*args):
    return subprocess.run(
        [sys.executable, BIN] + list(args),
        capture_output=True,
        text=True,
        cwd=ROOT,
        env={"PATH": "/usr/bin:/bin", "HOME": tempfile.gettempdir()},
    )


class ScanTests(unittest.TestCase):
    def test_bearer_in_dns_txt_is_an_error(self):
        findings, stats = scan_paths([EXAMPLES])
        rules = {(f.rule, f.context) for f in findings}
        self.assertIn(("BEARER_SECRET_PUBLISHED", "dns_txt"), rules)
        self.assertGreaterEqual(stats["files"], 2)

    def test_no_raw_address_in_report_by_default(self):
        findings, _ = scan_paths([EXAMPLES])
        blob = json.dumps([f.as_dict() for f in findings])
        self.assertNotIn(fixtures.no_psk(), blob)
        self.assertNotIn(fixtures.bearer(), blob)


class CliTests(unittest.TestCase):
    def test_scan_leaked_examples_exits_1_and_json_parses(self):
        proc = run("scan", EXAMPLES, "--json")
        self.assertEqual(proc.returncode, 1, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["schema"], 1)
        self.assertEqual(payload["summary"]["error"], 2)
        self.assertEqual(payload["worst_severity"], "error")
        rules = {f["rule"] for f in payload["findings"]}
        self.assertIn("BEARER_SECRET_PUBLISHED", rules)
        self.assertIn("NO_PSK_ADDRESS", rules)

    def test_scan_clean_directory_exits_0(self):
        proc = run("scan", os.path.join(EXAMPLES, "clean"), "--json")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["summary"]["error"], 0)
        self.assertEqual(payload["findings"][0]["rule"], "NO_PSK_ADDRESS")

    def test_scan_fail_on_none_always_exits_0(self):
        proc = run("scan", EXAMPLES, "--fail-on", "none")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("2 error(s)", proc.stdout)

    def test_scan_fail_on_warning_exits_1_on_warning_only_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "notes.md")
            with open(path, "w") as fh:
                fh.write("An address with a future field: %s\n" % fixtures.unknown_field())
            proc = run("scan", path, "--fail-on", "warning", "--json")
            self.assertEqual(proc.returncode, 1, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["summary"]["warning"], 1)
            self.assertEqual(payload["summary"]["error"], 0)

    def test_inspect_bearer_exits_1_and_hides_psk(self):
        addr = fixtures.bearer()
        proc = run("inspect", addr, "--json")
        self.assertEqual(proc.returncode, 1, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["verdict"], "bearer-secret")
        self.assertTrue(payload["address"]["has_psk"])
        self.assertNotIn(fixtures._key("bearer:psk").hex(), proc.stdout)
        self.assertNotIn(addr, proc.stdout)

    def test_inspect_no_psk_exits_0(self):
        proc = run("inspect", fixtures.no_psk(), "--json")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["verdict"], "publishable-no-psk")
        self.assertFalse(payload["address"]["has_psk"])

    def test_inspect_invalid_exits_2(self):
        proc = run("inspect", "tcnot-a-real-address", "--json")
        self.assertEqual(proc.returncode, 2)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["verdict"], "invalid")

    def test_scan_missing_path_exits_2(self):
        proc = run("scan", "/nonexistent/path/for/tailcat", "--json")
        self.assertEqual(proc.returncode, 2)

    def test_text_output_contains_location_and_fingerprint(self):
        proc = run("scan", EXAMPLES)
        self.assertEqual(proc.returncode, 1)
        self.assertRegex(proc.stdout, r"examples/in/leaked_notes\.md:\d+:\d+: ERROR BEARER_SECRET")
        self.assertIn("fp=", proc.stdout)
        self.assertIn("2 error(s)", proc.stdout)

    def test_no_derp_address_is_a_warning_not_invalid(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "addr.txt")
            with open(path, "w") as fh:
                fh.write("relay picked at runtime: %s\n" % fixtures.no_derp())
            proc = run("scan", path, "--json", "--fail-on", "warning")
            self.assertEqual(proc.returncode, 1, proc.stderr)
            payload = json.loads(proc.stdout)
            rules = {f["rule"] for f in payload["findings"]}
            self.assertIn("ADDR_NO_DERP", rules)
            self.assertNotIn("ADDR_CBOR_INVALID", rules)

    def test_show_address_opt_in(self):
        proc = run("scan", os.path.join(EXAMPLES, "clean"), "--json", "--show-address")
        payload = json.loads(proc.stdout)
        with open(os.path.join(EXAMPLES, "clean", "README.md")) as fh:
            committed = [tok for tok in fh.read().split() if tok.startswith("tc")][0]
        self.assertEqual(payload["findings"][0]["address"], committed)


if __name__ == "__main__":
    unittest.main()