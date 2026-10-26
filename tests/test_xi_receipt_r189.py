"""R18.9 Python candidate receipt: byte identity and refusal suite."""
import copy
import json
import pathlib
import sys
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"reference"/"python"))
import xi_receipt_r189 as receipt
import xi_pilot_r18 as pilot


class CanonicalReceiptTests(unittest.TestCase):
    def test_fixture_is_original_88_public_bytes(self):
        self.assertEqual(receipt.make("digest")["subject"]["sha256"],
                         pilot.sha(pilot.PAYLOAD))
        self.assertEqual(receipt.make("digest")["subject"]["bytes"],88)
        self.assertEqual(pilot.fixture()["sha256"],receipt.make("digest")["subject"]["sha256"])

    def test_four_cases_are_canonical_and_unapproved(self):
        self.assertEqual(len(receipt.CASES),4)
        for case in receipt.CASES:
            with self.subTest(case=case):
                b=receipt.emit(case)
                self.assertTrue(b.endswith(b"\n"))
                self.assertNotIn(b" ",b.replace(b"synthetic_public",b""))
                check=receipt.verify(b)
                self.assertEqual(check["status"],"CANONICAL_BYTES_MATCH_UNAUTHENTICATED")
                self.assertEqual(check["independent_signatures_verified"],0)
                self.assertEqual(check["approved_operations"],0)
                self.assertEqual(check["authority"],"none")
                self.assertFalse(check["live_xi_connected"])
                data=json.loads(b)
                self.assertEqual(data["observed_exchange"],False)
                self.assertTrue(data["example_only"])
                self.assertEqual(data["r17_external_pilot"],"BLOCKED")
                self.assertEqual(data["r18_real_two_host_pilot"],"NOT_RUN")

    def test_reject_newlines_pretty_keys_wrong_order_or_trailing_bytes(self):
        original=receipt.emit("digest")
        obj=receipt.make("digest")
        variants=[
            original.rstrip(b"\n"),
            original+b"\n",
            b" "+original,
            json.dumps(obj,indent=2).encode(),
            json.dumps(obj,sort_keys=False,separators=(",",":")).encode()+b"\n",
        ]
        for b in variants:
            with self.subTest(b=b[:45]):
                with self.assertRaises(receipt.Refused):
                    receipt.verify(b)

    def test_reject_duplicate_keys(self):
        original=receipt.emit("digest")
        duplicate=original.replace(b'"approved_operations":0,',
                                     b'"approved_operations":0,"approved_operations":0,',1)
        self.assertNotEqual(duplicate,original)
        with self.assertRaisesRegex(receipt.Refused,"duplicate"):
            receipt.verify(duplicate)

    def test_reject_false_authority_and_privileged_claims(self):
        edits=[
            ("authority","admin"),("live_xi_connected",True),
            ("operator_approvals",1),("approved_operations",1),
            ("observed_exchange",True),("independent_signatures_verified",1),
            ("r17_external_pilot","APPROVED"),("r18_real_two_host_pilot","PASS"),
            ("schema","Xi.Native.v1"),("parties",["authenticated-hunter","phi-sim"]),
            ("extra","hidden value"),
        ]
        for key,val in edits:
            obj=copy.deepcopy(receipt.make("digest"))
            obj[key]=val
            with self.subTest(key=key):
                with self.assertRaises(receipt.Refused):
                    receipt.verify(receipt.canonical(obj))

    def test_reject_subject_mutations(self):
        for name,value in [
            ("bytes",89),("sha256","0"*64),
            ("classification","secret"),("operation","repo.write"),
            ("origin","independently verified Xi sender"),
        ]:
            obj=copy.deepcopy(receipt.make("digest"))
            obj["subject"][name]=value
            with self.subTest(field=name):
                with self.assertRaises(receipt.Refused):
                    receipt.verify(receipt.canonical(obj))

    def test_ascii_subset_refuses_ambiguous_types_and_unicode(self):
        for v in [{"x":None},{"x":-1},{"x":1.25},{"x":"😀"},
                  {"x":"line\nbreak"},{"x":9007199254740992}]:
            with self.subTest(v=v):
                with self.assertRaises(receipt.Refused):
                    receipt.canonical(v)

    def test_unrecognized_case_refused(self):
        with self.assertRaises(receipt.Refused):
            receipt.emit("execute")
        self.assertEqual(receipt.main(["require-live"]),2)

if __name__=="__main__": unittest.main()
