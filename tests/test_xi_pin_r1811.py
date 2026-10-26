"""R18.11 Python local pin/rotation tests; NO authenticated partner identity."""
import copy
import json
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"reference"/"python"))
import xi_pin_policy_r1811 as pin
import xi_receipt_r189 as base
import xi_signed_receipt_r1810 as signed


class LocalPinTests(unittest.TestCase):
    def setUp(self):
        self.first=signed.create("digest")
        self.second=signed.create("digest")
        self.key_a=json.loads(self.first)["public_key_hex"]
        self.key_b=json.loads(self.second)["public_key_hex"]
        self.assertNotEqual(self.key_a,self.key_b)

    def test_mathematically_valid_signature_only_matches_separately_configured_key(self):
        p=pin.make_test_policy(self.key_a)
        result=pin.verify(self.first,p)
        self.assertEqual(result["status"],"LOCAL_SIMULATED_PIN_MATCH_AND_SIGNATURE_VALID_ONLY")
        self.assertTrue(result["signature_mathematically_valid"])
        self.assertTrue(result["simulated_local_pin_matched"])
        self.assertFalse(result["independent_partner_identity_verified"])
        self.assertFalse(result["out_of_band_key_authentication_verified"])
        self.assertEqual(result["operator_approvals"],0)
        self.assertEqual(result["approved_operations"],0)
        self.assertEqual(result["external_gates_promoted"],0)
        self.assertFalse(result["live_xi_connected"])
        self.assertEqual(result["authority"],"none")
        signed.verify(self.second)  # Its signature math is VALID.
        with self.assertRaisesRegex(pin.Refused,"different public key"):
            pin.verify(self.second,p)

    def test_rotation_requires_new_policy_and_revokes_old_key(self):
        original=pin.make_test_policy(self.key_a,epoch=1)
        rotated=pin.make_test_policy(self.key_b,revoked=[self.key_a],epoch=2)
        self.assertEqual(pin.verify(self.first,original)["policy_epoch"],1)
        self.assertEqual(pin.verify(self.second,rotated)["policy_epoch"],2)
        with self.assertRaisesRegex(pin.Refused,"revoked"):
            pin.verify(self.first,rotated)
        with self.assertRaises(pin.Refused):
            pin.verify(self.second,original)

    def test_reject_policy_authority_forgeries_and_malformed_key_roster(self):
        original=json.loads(pin.make_test_policy(self.key_a))
        edits=[
            ("external_identity_verified",True),
            ("operator_approvals",1),
            ("approved_operations",1),
            ("live_xi_connected",True),
            ("authority","admin"),
            ("policy_source","INDEPENDENTLY_VERIFIED_XI"),
            ("scope","repo.write"),
            ("active_public_key_hex","0"*64),
            ("revoked_public_key_hexes",[self.key_a]),
            ("revoked_public_key_hexes",[self.key_b,self.key_b]),
            ("epoch",0),
            ("epoch",2**53),
            ("unexpected_grant","secret"),
        ]
        for field,value in edits:
            updated=dict(original)
            updated[field]=value
            raw=base.canonical(updated) if field!="epoch" or value<2**53 else (
                json.dumps(updated).encode("ascii")+b"\n")
            with self.subTest(field=field,value=value):
                if field=="active_public_key_hex" and value=="0"*64:
                    # A different correctly formatted policy can exist, but
                    # cannot authenticate the original signer's envelope.
                    pin.parse_policy(raw)
                    with self.assertRaises(pin.Refused):
                        pin.verify(self.first,raw)
                else:
                    with self.assertRaises(Exception):
                        pin.parse_policy(raw)

    def test_fails_on_self_reported_or_noncanonical_policy(self):
        doc=json.loads(pin.make_test_policy(self.key_a))
        good=pin.make_test_policy(self.key_a)
        variants=[
            good.rstrip(b"\n"), good+b"\n",
            json.dumps(doc,indent=2).encode("ascii"),
            good.replace(b'"approved_operations":0,',
                         b'"approved_operations":0,"approved_operations":0,',1),
        ]
        for v in variants:
            with self.assertRaises(Exception):
                pin.parse_policy(v)

    def test_invalid_signature_is_rejected_even_with_pinned_key(self):
        raw=json.loads(self.first)
        raw["signature_hex"]="0"*128
        with self.assertRaises(Exception):
            pin.verify(base.canonical(raw),pin.make_test_policy(self.key_a))

    def test_no_operator_power_and_no_live_mode(self):
        with self.assertRaises(Exception):
            pin.parse_policy(b'{"authority":"none"}\n')
        self.assertEqual(pin.main(["require-live"]),2)

if __name__=="__main__":
    unittest.main()
