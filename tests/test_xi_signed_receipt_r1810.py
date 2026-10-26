"""R18.10 Python Ed25519: math can verify, real Xi identity CANNOT."""
import json
import pathlib
import sys
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"reference"/"python"))
import xi_signed_receipt_r1810 as signed
import xi_receipt_r189 as base


class EphemeralSignedReceiptTests(unittest.TestCase):
    def test_four_new_ephemeral_keys_and_unsigned_payloads(self):
        keys=[]
        for case in base.CASES:
            with self.subTest(case=case):
                raw=signed.create(case)
                info=signed.verify(raw)
                data=json.loads(raw)
                self.assertEqual(info["status"],"SELF_ISSUED_EPHEMERAL_SIGNATURE_MATH_VALID")
                self.assertTrue(info["self_issued_signature_verified"])
                self.assertFalse(info["independent_partner_identity_verified"])
                self.assertEqual(info["operator_approvals"],0)
                self.assertEqual(info["approved_operations"],0)
                self.assertEqual(info["external_gates_promoted"],0)
                self.assertFalse(info["real_two_host_crossing_tested"])
                self.assertEqual(info["authority"],"none")
                self.assertFalse(data["real_xi_identity_verified"])
                self.assertFalse(data["signed_exchange_observed"])
                self.assertEqual(data["r17_external_pilot"],"BLOCKED")
                self.assertEqual(data["r18_real_two_host_pilot"],"NOT_RUN")
                self.assertEqual(base.verify(__import__("base64").b64decode(data["receipt_b64"]))["case_id"],case)
                keys.append(data["public_key_hex"])
        self.assertEqual(len(set(keys)),len(keys),"ephemeral test signer reused a key")

    def test_all_authority_promotions_and_signature_changes_refused(self):
        raw=signed.create("digest")
        doc=json.loads(raw)
        changes=[
            ("real_xi_identity_verified",True),
            ("bilateral_consent_verified",True),
            ("approved_operations",1),
            ("signed_exchange_observed",True),
            ("authority","admin"),
            ("live_xi_connected",True),
            ("self_issued",False),
            ("signer_classification","AUTHENTICATED_HUNTER"),
            ("suite","Xi.Native.v1"),
            ("r17_external_pilot","CLEARED"),
            ("r18_real_two_host_pilot","PASS"),
            ("extra_private_claim","yes"),
            ("receipt_sha256","0"*64),
            ("domain_message_sha256","0"*64),
            ("signature_hex","0"*128),
            ("public_key_hex","0"*64),
        ]
        for field,value in changes:
            with self.subTest(field=field):
                bad=dict(doc);bad[field]=value
                with self.assertRaises(Exception):
                    signed.verify(base.canonical(bad))

    def test_case_rebinding_and_swapping_signer_refused(self):
        a=json.loads(signed.create("digest"))
        b=json.loads(signed.create("policy"))
        for field in ("public_key_hex","signature_hex","receipt_b64"):
            changed=dict(a)
            changed[field]=b[field]
            with self.subTest(field=field):
                with self.assertRaises(Exception):
                    signed.verify(base.canonical(changed))

    def test_noncanonical_json_and_duplicate_key_refused(self):
        raw=signed.create("digest")
        variants=[
            raw.rstrip(b"\n"),
            raw+b"\n",
            b" "+raw,
            json.dumps(json.loads(raw),indent=2).encode(),
            raw.replace(b'"approved_operations":0,',
                        b'"approved_operations":0,"approved_operations":0,',1),
        ]
        for variant in variants:
            with self.assertRaises(Exception):
                signed.verify(variant)

    def test_error_on_unreviewed_case_and_live_request(self):
        with self.assertRaises(Exception):
            signed.create("repo.write")
        self.assertEqual(signed.main(["require-live"]),2)

if __name__=="__main__":
    unittest.main()
