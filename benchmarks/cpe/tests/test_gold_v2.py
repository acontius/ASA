import json
import tempfile
import unittest
from pathlib import Path

from benchmarks.cpe.src.dataset import create_annotation_manifest, stable_id
from benchmarks.cpe.src.gold import canonical_source_hash, load_gold_annotations, migrate_v1_file, validate_gold_v2
from benchmarks.cpe.src.metrics import evaluate


MAPPED_CPE = "cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*"


def identity(identity_id, product, vendor=None, version=None, mapping="not_in_dictionary", cpe=None, alternatives=None):
    return {"identity_id":identity_id,"expected_product":product,"expected_vendor":vendor,"expected_version":version,"expected_update":None,"expected_part":"a","cpe_mapping_status":mapping,"expected_cpe23":cpe,"acceptable_cpes":alternatives or [],"evidence_paths":["t22.ssh.result.server_id.software"],"adjudication_notes":""}


def gold(record_id, identities, status="reviewed", source_hash="a"*64):
    return {"schema_version":"2.0","record_id":record_id,"source_hash":source_hash,"annotation_status":status,"expected_identities":identities,"annotation":{"annotator_id":"human-1","reviewed_at":None,"adjudication_status":"reviewed","reviewer_id":"human-2","notes":""}}


class GoldV2Tests(unittest.TestCase):
    def test_record_id_is_stable_across_content_edits_and_hash_detects_them(self):
        before={"_id":"source-1","_source":{"software":"Example 1.0"}}
        after={"_id":"source-1","_source":{"software":"Example 2.0"}}
        self.assertEqual(stable_id(before,1),stable_id(after,1))
        self.assertNotEqual(canonical_source_hash(before),canonical_source_hash(after))

    def test_zero_expected_identities_is_explicit_no_software_state(self):
        row=gold("r",[],"no_software_identity")
        self.assertEqual(validate_gold_v2(row),[])
        result=evaluate([{"record_id":"r","source_hash":row["source_hash"],"extraction_predictions":[]}],{"r":row})
        self.assertEqual(result["scored_records_without_identities"],1)
        self.assertEqual(result["evaluation_tracks"]["extraction_only"]["no_software_identity_correct_records"],1)

    def test_one_identity_scores_normalized_fields_and_mapped_cpe(self):
        row=gold("r",[identity("r-1","OpenSSH","OpenBSD","9.6p1","mapped",MAPPED_CPE)])
        prediction={"candidate_id":"p1","product_name":"open_ssh","vendor":"openbsd","version":"9.6P1","part":"A","abstain":False}
        result=evaluate([{"record_id":"r","source_hash":row["source_hash"],"extraction_predictions":[prediction],"final_cpe_resolutions":[{"candidate_id":"p1","cpe23":MAPPED_CPE,"identity_valid":True}]}],{"r":row})
        self.assertEqual(result["identity_metrics"]["f1"],1)
        self.assertEqual(result["exact_cpe_accuracy"],1)

    def test_multiple_products_are_order_independent_one_to_one_sets(self):
        row=gold("r",[identity("r-a","nginx","f5","1.24"),identity("r-b","OpenSSH","OpenBSD","9.6p1")])
        predictions=[{"candidate_id":"ssh","product_name":"open_ssh","vendor":"openbsd","version":"9.6P1"},{"candidate_id":"web","product_name":"nginx","vendor":"f5","version":"1.24"}]
        first=evaluate([{"record_id":"r","source_hash":row["source_hash"],"extraction_predictions":predictions}],{"r":row})
        second=evaluate([{"record_id":"r","source_hash":row["source_hash"],"extraction_predictions":list(reversed(predictions))}],{"r":row})
        self.assertEqual(first["identity_metrics"]["f1"],1)
        self.assertEqual(second["identity_metrics"]["f1"],1)

    def test_two_versions_of_same_product_match_distinct_identities(self):
        row=gold("r",[identity("v1","nginx","f5","1.24"),identity("v2","nginx","f5","1.26")])
        predictions=[{"candidate_id":"p2","product_name":"nginx","vendor":"f5","version":"1.26"},{"candidate_id":"p1","product_name":"nginx","vendor":"f5","version":"1.24"}]
        result=evaluate([{"record_id":"r","source_hash":row["source_hash"],"extraction_predictions":predictions}],{"r":row})
        self.assertEqual(result["identity_metrics"]["recall"],1)
        self.assertEqual(result["identity_metrics"]["precision"],1)

    def test_matching_maximizes_component_agreement_after_identity_cardinality(self):
        row=gold("r",[identity("vendor-known","OpenSSH","OpenBSD",None),identity("version-known","OpenSSH",None,"9.6p1")])
        predictions=[
            {"candidate_id":"vendor-only","product_name":"OpenSSH","vendor":"OpenBSD","version":None},
            {"candidate_id":"version-known","product_name":"OpenSSH","vendor":"OpenBSD","version":"9.6p1"},
        ]
        result=evaluate([{"record_id":"r","source_hash":row["source_hash"],"extraction_predictions":predictions}],{"r":row})
        tracks=result["evaluation_tracks"]["extraction_only"]
        self.assertEqual(result["identity_metrics"]["f1"],1)
        self.assertEqual(tracks["vendor_metrics"]["f1"],1)
        self.assertEqual(tracks["version_metrics"]["f1"],1)

    def test_missing_and_additional_identities_are_penalized(self):
        row=gold("r",[identity("a","nginx","f5","1.24"),identity("b","openssh","openbsd","9.6")])
        missing=evaluate([{"record_id":"r","source_hash":row["source_hash"],"extraction_predictions":[]}],{"r":row})
        self.assertEqual(missing["identity_metrics"]["recall"],0)
        extra=evaluate([{"record_id":"r","source_hash":row["source_hash"],"extraction_predictions":[{"product_name":"nginx","vendor":"f5","version":"1.24"},{"product_name":"openssh","vendor":"openbsd","version":"9.6"},{"product_name":"apache","version":"2.4"}]}],{"r":row})
        self.assertEqual(extra["identity_metrics"]["precision"],2/3)

    def test_uncertain_statuses_are_excluded_not_negative(self):
        rows={status:gold(status,[identity(status+"-id","x")],status) for status in ("ambiguous","insufficient_evidence","out_of_scope","unreviewed")}
        result=evaluate([{"record_id":status,"source_hash":row["source_hash"],"extraction_predictions":[]} for status,row in rows.items()],rows)
        self.assertEqual(result["scored_records"],0)
        self.assertIsNone(result["identity_metrics"]["f1"])
        self.assertEqual(result["gold_status_counts"]["ambiguous"],1)

    def test_pending_adjudication_is_not_primary_scoring_gold(self):
        row=gold("r",[identity("r-1","OpenSSH")])
        row["annotation"]["adjudication_status"]="pending"
        result=evaluate([{"record_id":"r","source_hash":row["source_hash"],"extraction_predictions":[]}],{"r":row})
        self.assertEqual(result["scored_records"],0)
        self.assertEqual(result["gold_adjudication_status_counts"]["pending"],1)

    def test_mapped_and_unmapped_cpe_identities_are_reported_separately(self):
        mapped=identity("m","openssh","openbsd","9.6p1","mapped",MAPPED_CPE)
        unmapped=identity("u","nginx","f5","1.26","not_in_dictionary")
        row=gold("r",[mapped,unmapped])
        result=evaluate([{"record_id":"r","source_hash":row["source_hash"],"extraction_predictions":[]}],{"r":row})
        end=result["evaluation_tracks"]["end_to_end_cpe"]
        self.assertEqual(end["mapped_gold_identities"],1)
        self.assertEqual(end["unmapped_identity_counts"]["not_in_dictionary"],1)
        self.assertEqual(end["exact_cpe_accuracy"],0)

    def test_unreviewed_mapping_remains_extraction_gold_but_is_excluded_from_cpe_scoring(self):
        row=gold("r",[identity("r-1","OpenSSH","OpenBSD","9.6p1","unreviewed")])
        prediction={"product_name":"OpenSSH","vendor":"OpenBSD","version":"9.6p1","part":"a","abstain":False}
        self.assertEqual(validate_gold_v2(row),[])
        result=evaluate([{"record_id":"r","source_hash":row["source_hash"],"extraction_predictions":[prediction]}],{"r":row})
        extraction=result["evaluation_tracks"]["extraction_only"]
        cpe=result["evaluation_tracks"]["end_to_end_cpe"]
        self.assertEqual(result["scored_records"],1)
        self.assertEqual(extraction["identity_metrics"]["f1"],1)
        self.assertEqual(cpe["mapped_gold_identities"],0)
        self.assertIsNone(cpe["exact_cpe_accuracy"])
        self.assertEqual(cpe["unmapped_identity_counts"]["unreviewed"],1)

    def test_end_to_end_cpe_track_is_independent_and_one_to_one(self):
        first=identity("first","OpenSSH","OpenBSD","9.6p1","mapped",MAPPED_CPE)
        second=identity("second","OpenSSH","OpenBSD","9.6p1","mapped",MAPPED_CPE)
        row=gold("r",[first,second])
        result=evaluate([{"record_id":"r","source_hash":row["source_hash"],"extraction_predictions":[],"final_cpe_resolutions":[{"cpe23":MAPPED_CPE,"identity_valid":True}]}],{"r":row})
        end=result["evaluation_tracks"]["end_to_end_cpe"]
        self.assertEqual(end["exact_cpe_correct_identities"],1)
        self.assertEqual(end["exact_cpe_accuracy"],0.5)

    def test_stale_source_hash_is_excluded_and_counted(self):
        row=gold("r",[identity("r-1","openssh")])
        result=evaluate([{"record_id":"r","source_hash":"b"*64,"extraction_predictions":[]}],{"r":row})
        self.assertEqual(result["stale_source_records"],1)
        self.assertEqual(result["scored_records"],0)
        self.assertIsNone(result["exact_cpe_accuracy"])

    def test_empty_gold_does_not_report_zero_accuracy(self):
        result=evaluate([{"record_id":"r","extraction_predictions":[]}],{})
        self.assertIsNone(result["exact_cpe_accuracy"])
        self.assertIsNone(result["identity_metrics"]["f1"])

    def test_schema_and_evidence_validation(self):
        document={"t22":{"ssh":{"result":{"server_id":{"software":"OpenSSH_9.6p1"}}}}}
        row=gold("r",[identity("r-1","OpenSSH","OpenBSD","9.6p1","mapped",MAPPED_CPE)])
        row["source_hash"]=canonical_source_hash(document)
        self.assertEqual(validate_gold_v2(row,document),[])
        row["expected_identities"][0]["evidence_paths"]=["t22.ssh.missing"]
        self.assertTrue(any("evidence path does not exist" in error for error in validate_gold_v2(row,document)))
        row["expected_identities"][0]["evidence_paths"]=["t22.ssh.result.server_id.software"]
        self.assertIn("source_hash does not match", " ".join(validate_gold_v2(row,{"changed":True})))

    def test_gold_cpe_components_must_match_identity_but_allow_unspecified_wildcards(self):
        good=identity("r-1","OpenSSH","OpenBSD","9.6p1","mapped",MAPPED_CPE)
        self.assertEqual(validate_gold_v2(gold("r",[good])),[])
        wrong=identity("r-1","OpenSSH","OpenBSD","9.7p1","mapped",MAPPED_CPE)
        self.assertIn("CPE version does not match expected identity"," ".join(validate_gold_v2(gold("r",[wrong]))))
        wildcard="cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"
        unspecified=identity("r-1","OpenSSH","OpenBSD",None,"mapped",wildcard)
        self.assertEqual(validate_gold_v2(gold("r",[unspecified])),[])

    def test_v1_loader_is_explicit_and_migration_never_overwrites_source(self):
        document={"_id":"raw-1","_source":{"proto":"ssh","t22":{"ssh":{"result":{"server_id":{"software":"OpenSSH_9.6p1"}}}}}}
        record_id="rec-"+__import__("hashlib").sha256(json.dumps(document,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()[:16]
        legacy={"record_id":record_id,"expected_product":"OpenSSH","expected_vendor":"openbsd","expected_version":"9.6p1","expected_update":None,"expected_part":"a","expected_cpe23":MAPPED_CPE,"acceptable_cpes":[],"abstain_expected":False,"evidence_paths":["_source.t22.ssh.result.server_id.software"],"adjudication_notes":"old label","scoring_status":"reviewed"}
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); old=root/"gold-v1.jsonl"; source=root/"input.jsonl"; migrated=root/"gold-v2.jsonl"
            old_bytes=(json.dumps(legacy)+"\n").encode(); old.write_bytes(old_bytes); source.write_text(json.dumps(document)+"\n")
            loaded,errors=load_gold_annotations(old)
            self.assertFalse(errors); self.assertEqual(loaded[record_id]["_source_format"],"v1")
            self.assertEqual(migrate_v1_file(old,migrated,source),1)
            self.assertEqual(old.read_bytes(),old_bytes)
            upgraded=json.loads(migrated.read_text())
            self.assertEqual(upgraded["annotation_status"],"unreviewed")
            self.assertEqual(upgraded["record_id"],stable_id(document,1))
            self.assertEqual(validate_gold_v2(upgraded,document),[])
            with self.assertRaises(FileExistsError):migrate_v1_file(old,migrated,source)

    def test_annotation_manifest_skips_malformed_rows_and_is_reproducible(self):
        source_document={"_id":"r","_source":{"proto":"ssh","path":"/x","ip":"127.0.0.1","scanTime":"1","port":"t22","appId":"x","t22":{"ssh":{"result":{"server_id":{"software":"OpenSSH_9.6p1"}}}}}}
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); source=root/"input.jsonl"; output=root/"manifest.jsonl"
            source.write_bytes((json.dumps(source_document)+"\n{bad json\n[]\n").encode()+b"\xff\n")
            first=create_annotation_manifest(source,output,10,19); bytes_one=output.read_bytes()
            second=create_annotation_manifest(source,output,10,19)
            self.assertEqual(bytes_one,output.read_bytes())
            self.assertEqual(first["malformed_json_rows"],2)
            self.assertEqual(first["non_object_rows"],1)
            manifest=json.loads(output.read_text().splitlines()[0])
            self.assertIn("source_hash",manifest);self.assertNotIn("raw",manifest)
            self.assertEqual(first["records"],second["records"])


if __name__ == "__main__":
    unittest.main()
