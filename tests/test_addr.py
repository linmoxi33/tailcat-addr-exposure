import base64
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

import fixtures  # noqa: E402
from tailcat_addr_exposure import cbor  # noqa: E402
from tailcat_addr_exposure.addr import AddrError, parse_address  # noqa: E402


class ParseTests(unittest.TestCase):
    def test_bearer_address_reports_psk_but_never_key_material(self):
        addr = fixtures.bearer()
        parsed = parse_address(addr)
        self.assertTrue(parsed.has_psk)
        self.assertFalse(parsed.zero_psk)
        dumped = repr(parsed.as_dict())
        psk = fixtures._key("bearer:psk")
        self.assertNotIn(psk.hex(), dumped)
        self.assertNotIn(psk.hex()[:16], dumped)
        self.assertNotIn(addr[10:40], dumped)

    def test_no_psk_address_is_publishable(self):
        parsed = parse_address(fixtures.no_psk())
        self.assertFalse(parsed.has_psk)
        self.assertEqual(parsed.region_id, 2)
        self.assertTrue(parsed.has_disco)

    def test_embedded_derp_regions_are_summarized(self):
        parsed = parse_address(fixtures.embedded_derp())
        self.assertEqual(len(parsed.regions), 1)
        self.assertEqual(parsed.regions[0]["region_code"], "test")
        self.assertEqual(parsed.regions[0]["node_count"], 2)
        self.assertEqual(parsed.regions[0]["region_id"], 900)

    def test_missing_server_key_is_rejected(self):
        with self.assertRaises(AddrError) as ctx:
            parse_address(fixtures.missing_server_key())
        self.assertEqual(ctx.exception.rule, "ADDR_NO_SERVER_KEY")
        self.assertEqual(ctx.exception.severity, "error")

    def test_short_server_key_is_rejected(self):
        with self.assertRaises(AddrError) as ctx:
            parse_address(fixtures.bad_key_length())
        self.assertEqual(ctx.exception.rule, "ADDR_BAD_SERVER_KEY")

    def test_trailing_bytes_are_rejected(self):
        with self.assertRaises(AddrError) as ctx:
            parse_address(fixtures.trailing_bytes())
        self.assertEqual(ctx.exception.rule, "ADDR_TRAILING_BYTES")

    def test_padded_base64_is_rejected(self):
        with self.assertRaises(AddrError) as ctx:
            parse_address(fixtures.no_psk() + "==")
        self.assertEqual(ctx.exception.rule, "ADDR_PADDED_BASE64")

    def test_duplicate_cbor_keys_are_rejected(self):
        # map(2) {"p": <32 bytes>, "p": <32 bytes>}
        raw = b"\xa2" + cbor.dumps("p") + cbor.dumps(b"\x11" * 32) + cbor.dumps("p") + cbor.dumps(b"\x22" * 32)
        addr = "tc" + base64.urlsafe_b64encode(raw).decode().rstrip("=")
        with self.assertRaises(AddrError) as ctx:
            parse_address(addr)
        self.assertEqual(ctx.exception.rule, "ADDR_CBOR_INVALID")

    def test_unknown_field_is_reported_not_fatal(self):
        parsed = parse_address(fixtures.unknown_field())
        self.assertEqual(parsed.unknown_fields, ["z"])

    def test_zero_region_id_is_valid_but_flagged(self):
        # Upstream marshals RegionID with omitempty; ParseAddr accepts the result.
        parsed = parse_address(fixtures.no_derp())
        self.assertTrue(parsed.no_derp)
        self.assertIsNone(parsed.region_id)
        self.assertFalse(parsed.as_dict()["has_derp_info"])

    def test_fingerprint_is_stable_and_short_form_is_redacted(self):
        addr = fixtures.no_psk()
        a = parse_address(addr)
        b = parse_address(addr)
        self.assertEqual(a.fingerprint, b.fingerprint)
        self.assertNotIn(addr[2:30], a.masked)


if __name__ == "__main__":
    unittest.main()